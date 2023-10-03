#include "balancer.h"
#include "controlplane.h"

eResult balancer_t::init()
{
	service_counters.init(&controlPlane->counter_manager);
	real_counters.init(&controlPlane->counter_manager);

	for (unsigned int i = 1;
	     i < YANET_CONFIG_BALANCER_REALS_SIZE;
	     i++)
	{
		reals_unordered_ids_unused.emplace(i);
	}

	controlPlane->register_command(common::icp::requestType::balancer_config, [this]()
	{
		return balancer_config();
	});

	controlPlane->register_command(common::icp::requestType::balancer_summary, [this]()
	{
		return balancer_summary();
	});

	controlPlane->register_command(common::icp::requestType::balancer_service, [this](const common::icp::request& request)
	{
		return balancer_service(std::get<common::icp::balancer_service::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::balancer_real_find, [this](const common::icp::request& request)
	{
		return balancer_real_find(std::get<common::icp::balancer_real_find::request>(std::get<1>(request)));
	});

    	controlPlane->register_command(common::icp::requestType::balancer_real, [this](const common::icp::request& request)
	{
		return balancer_real(std::get<common::icp::balancer_real::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::balancer_real_flush, [this]()
	{
		return balancer_real_flush();
	});

	controlPlane->register_command(common::icp::requestType::balancer_announce, [this]()
	{
		return balancer_announce();
	});

	controlPlane->register_service(this);

	funcThreads.emplace_back([this]()
	{
		counters_gc_thread();
	});

	funcThreads.emplace_back([this]()
	{
		reconfigure_wlc_thread();
	});

	return eResult::success;
}

inline void setip(common::icp_proto::IPAddr* pAddr, const ip_address_t& value)
{
	if (value.is_ipv4())
	{
		pAddr->set_ipv4(uint32_t(value.get_ipv4()));
	}
	else
	{
		pAddr->set_ipv6(value.get_ipv6().data(), 16);
	}
}

inline common::ip_address_t convert_to_ip_address(const common::icp_proto::IPAddr& proto_ipaddr)
{
	if (proto_ipaddr.has_ipv4())
	{
		return common::ipv4_address_t(proto_ipaddr.ipv4());
	}
	else
	{
		return common::ipv6_address_t((uint8_t*)proto_ipaddr.ipv6().data());
	}
}

void balancer_t::RealFind(
    ::google::protobuf::RpcController* /*controller*/,
    const ::common::icp_proto::BalancerRealFindRequest* req,
    ::common::icp_proto::BalancerRealFindResponse* resp,
    ::google::protobuf::Closure*)
{
	auto response = balancer_real_find({!req->module().empty() ? std::optional<std::string>{req->module()} : std::nullopt,
	                                    req->has_virtual_ip() ? std::optional<common::ip_address_t>{convert_to_ip_address(req->virtual_ip())} : std::nullopt,
	                                    req->proto() != common::icp_proto::NetProto::undefined ? std::optional<uint8_t>{req->proto() == common::icp_proto::NetProto::tcp ? IPPROTO_TCP : IPPROTO_UDP} : std::nullopt,
	                                    req->has_virtual_port() ? std::optional<uint16_t>{req->virtual_port()} : std::nullopt,
	                                    req->has_real_ip() ? std::optional<common::ip_address_t>{convert_to_ip_address(req->real_ip())} : std::nullopt,
	                                    req->has_real_port() ? std::optional<uint16_t>{req->real_port()} : std::nullopt});

	for (const auto& [key, value] : response)
	{
		auto balancer_data = resp->add_balancers();
		const auto& [id, module] = key;
		balancer_data->set_balancer_id(id);
		balancer_data->set_module(module.data());
		for (const auto& [service_key, service_value] : value)
		{
			auto proto_service = balancer_data->add_services();
			const auto& [vip, proto, port] = service_key;
			auto proto_service_key = proto_service->mutable_key();
			setip(proto_service_key->mutable_ip(), vip);
			switch (proto)
			{
			case IPPROTO_TCP:
				proto_service_key->set_proto(::common::icp_proto::NetProto::tcp);
				break;
			case IPPROTO_UDP:
				proto_service_key->set_proto(::common::icp_proto::NetProto::udp);
				break;
			}
			proto_service_key->set_port(port);

			const auto& [scheduler, version, reals] = service_value;

			proto_service->set_scheduler(scheduler.data());
			if (version.has_value())
			{
				proto_service->set_version(version->data());
			}

			for (const auto& [ip, port, enabled, weight, connections, packets, bytes] : reals)
			{
				auto proto_real = proto_service->add_reals();
				setip(proto_real->mutable_ip(), ip);
				proto_real->set_port(port);
				proto_real->set_enabled(enabled);
				proto_real->set_weight(weight);
				proto_real->set_connections(connections);
				proto_real->set_packets(packets);
				proto_real->set_bytes(bytes);
			}
		}
	}
}

void balancer_t::Real(
    google::protobuf::RpcController* /*controller*/,
    const ::common::icp_proto::BalancerRealRequest* req,
    ::common::icp_proto::Empty* /*resp*/,
    ::google::protobuf::Closure*)
{
	common::icp::balancer_real::request request;
	request.reserve(req->reals().size());
	for (const auto& real: req->reals()){
		request.push_back({real.module(),
			    convert_to_ip_address(real.virtual_ip()),
			    real.proto() == common::icp_proto::NetProto::tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    real.virtual_port(),
			    convert_to_ip_address(real.real_ip()),
			    real.real_port(),
			    real.enable(),
			    real.has_weight() ? std::optional<uint32_t>(real.weight()) : std::nullopt});
	}

	balancer_real(request);
}

void balancer_t::RealFlush(
    google::protobuf::RpcController* /*controller*/,
    const ::common::icp_proto::Empty* /*req*/,
    ::common::icp_proto::Empty* /*resp*/,
    ::google::protobuf::Closure*)
{
	balancer_real_flush();
}

void balancer_t::limit(common::icp::limit_summary::response& limits) const
{
	{
		auto config_current_guard = generations_config.current_lock_guard();
		limit_insert(limits,
		             "balancer.services",
		             generations_config.current().services_count,
		             YANET_CONFIG_BALANCER_SERVICES_SIZE);
		limit_insert(limits,
		             "balancer.reals",
		             std::nullopt,
		             generations_config.current().reals_count,
		             YANET_CONFIG_BALANCER_REALS_SIZE);
	}

	{
		auto services_current_guard = generations_services.current_lock_guard();
		limit_insert(limits,
		             "balancer.reals_enabled",
		             generations_services.current().reals_enabled_count,
		             YANET_CONFIG_BALANCER_REALS_SIZE);
	}
}

void balancer_t::controlplane_values(common::icp::controlplane_values::response& controlplane_values) const
{
	{
		std::lock_guard<std::mutex> guard(reals_unordered_mutex);
		controlplane_values.emplace_back("balancer.reals_unordered.size", std::to_string(reals_unordered.size()));
		controlplane_values.emplace_back("balancer.reals_unordered_ids_unused.size", std::to_string(reals_unordered_ids_unused.size()));
	}
	controlplane_values.emplace_back("balancer.real_counters.size", std::to_string(real_counters.get_counters().size()));
}

void balancer_t::reload_before()
{
	generations_config.next_lock();
}

void balancer_t::reload(const controlplane::base_t& base_prev,
                        const controlplane::base_t& base_next,
                        common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);

	for (const auto& [module_name, balancer] : base_prev.balancers)
	{
		for (const auto& [service_id, virtual_ip, proto, virtual_port, version, scheduler, scheduler_params, forwarding_method, flags, reals] : balancer.services)
		{
			(void)service_id;
			(void)version;
			(void)scheduler;
			(void)scheduler_params;
			(void)reals;
			(void)flags;
			(void)forwarding_method;

			service_counters.remove({module_name, {virtual_ip, proto, virtual_port}});

			for (const auto& [real_ip, real_port, real_weight] : reals)
			{
				(void)real_weight;

				const std::tuple<std::string,
				                 balancer::service_key_t,
				                 balancer::real_key_t> key = {module_name,
				                                              {virtual_ip, proto, virtual_port},
				                                              {real_ip, real_port}};

				real_counters.remove(key, base_prev.variables.find("balancer_real_timeout")->second.value);
			}
		}
	}


	for (const auto& [module_name, balancer] : base_next.balancers)
	{
		std::unordered_set<std::tuple<common::ip_address_t, uint16_t, uint8_t>> vip_vport_proto;

		for (const auto& [service_id, virtual_ip, proto, virtual_port, version, scheduler, scheduler_params, forwarding_method, flags, reals] : balancer.services)
		{
			(void)service_id;
			(void)version;
			(void)scheduler;
			(void)scheduler_params;
			(void)flags;
			(void)forwarding_method;

			service_counters.insert({module_name, {virtual_ip, proto, virtual_port}});

			vip_vport_proto.insert({virtual_ip, virtual_port, proto});

			for (const auto& [real_ip, real_port, real_weight] : reals)
			{
				(void)real_weight;

				const std::tuple<std::string,
				                 balancer::service_key_t,
				                 balancer::real_key_t> key = {module_name,
				                                              {virtual_ip, proto, virtual_port},
				                                              {real_ip, real_port}};

				real_counters.insert(key);
			}
		}

		dataplane.update_vip_vport_proto({balancer.balancer_id, vip_vport_proto});
	}

	service_counters.allocate();
	real_counters.allocate([&](const auto& key)
	{
		/// new counter

		std::lock_guard<std::mutex> guard(reals_unordered_mutex);

		uint32_t real_unordered_id = *reals_unordered_ids_unused.begin();
		reals_unordered_ids_unused.erase(real_unordered_id);

		reals_unordered.emplace(key, real_unordered_id);
	});

	compile(globalbase, generations_config.next());

}

void balancer_t::reload_after()
{
	service_counters.release();
	real_counters.release([&](const auto& key)
	{
		/// remove counter

		std::lock_guard<std::mutex> guard(reals_unordered_mutex);
		auto it = reals_unordered.find(key);
		if (it != reals_unordered.end())
		{
			reals_unordered_ids_unused.emplace(it->second);
			reals_unordered.erase(it);
		}
		else
		{
			/// @todo: error++
		}
	});

	{
		std::lock_guard<std::mutex> guard(config_switch_mutex);

		common::idp::updateGlobalBaseBalancer::request balancer;
		flush_reals(balancer, generations_config.next());
		dataplane.updateGlobalBaseBalancer(balancer);

		generations_services.next_lock();
		update_service(generations_config.next(), generations_services.next());
		generations_services.switch_generation();

		generations_config.switch_generation();

		generations_services.next_unlock();
		generations_config.next_unlock();
	}
}

common::icp::balancer_config::response balancer_t::balancer_config() const
{
	auto config_current_guard = generations_config.current_lock_guard();
	return generations_config.current().config_balancers;
}

common::icp::balancer_summary::response balancer_t::balancer_summary() const
{
	generations_config.current_lock();
	std::map<std::string, balancer_id_t> name_id = generations_config.current().name_id;
	generations_config.current_unlock();

	generations_services.current_lock();
	common::icp::balancer_summary::response response = generations_services.current().summary;
	generations_services.current_unlock();

	interface::dataPlane dataplane;
	auto balancer_service_connections = dataplane.balancer_service_connections(); ///< @todo: balancer_summary_connections

	for (auto& [response_module_name, response_services, response_reals_enabled, response_reals, response_connections, response_next_module] : response)
	{
		(void)response_services;
		(void)response_reals_enabled;
		(void)response_reals;
		(void)response_next_module;

		auto it = name_id.find(response_module_name);
		if (it == name_id.end())
		{
			continue;
		}

		auto response_module_id = it->second;

		response_connections = 0;
		for (const auto& [socket_id, service_connections] : balancer_service_connections)
		{
			(void)socket_id;

			uint32_t socket_connections = 0;
			for (const auto& [key, value] : service_connections)
			{
				const auto& [balancer_id, virtual_ip, proto, virtual_port] = key;
				(void)virtual_ip;
				(void)proto;
				(void)virtual_port;

				if (response_module_id == balancer_id)
				{
					socket_connections += value.value;
				}
			}

			if (socket_connections > response_connections)
			{
				response_connections = socket_connections;
			}
		}
	}

	return response;
}

common::icp::balancer_service::response balancer_t::balancer_service(const common::icp::balancer_service::request& request) const
{
	common::icp::balancer_service::response response;

	const auto& [filter_module, filter_virtual_ip, filter_proto, filter_virtual_port] = request;

	generations_services.current_lock();
	common::icp::balancer_service::response services = generations_services.current().services;
	generations_services.current_unlock();

	const auto counters = service_counters.get_counters();

	for (auto& [module, balancer] : services)
	{
		const auto& [module_id, module_name] = module;
		(void)module_id;

		if (filter_module &&
		    module_name != *filter_module)
		{
			continue;
		}

		for (auto& [service_key, service] : balancer)
		{
			const auto& [virtual_ip, proto, virtual_port] = service_key;

			if (filter_virtual_ip &&
			    virtual_ip != *filter_virtual_ip)
			{
				continue;
			}

			if (filter_proto &&
			    proto != *filter_proto)
			{
				continue;
			}

			if (filter_virtual_port &&
			    virtual_port != *filter_virtual_port)
			{
				continue;
			}

			response[module][service_key].swap(service);

			auto& [scheduler, version, connections, packets, bytes] = response[module][service_key];
			(void)scheduler;
			(void)version;
			(void)connections; ///< @todo: DELETE

			auto it = counters.find({module_name,
			                         {virtual_ip, proto, virtual_port}});
			if (it != counters.end())
			{
				packets = (it->second)[0];
				bytes = (it->second)[1];
			}
		}
	}

	return response;
}

common::icp::balancer_real_find::response balancer_t::balancer_real_find(const common::icp::balancer_real_find::request& request) const
{
	common::icp::balancer_real_find::response response;

	const auto& [filter_module, filter_virtual_ip, filter_proto, filter_virtual_port, filter_real_ip, filter_real_port] = request;

	generations_services.current_lock();
	common::icp::balancer_real_find::response reals = generations_services.current().reals;
	generations_services.current_unlock();

	const auto counters = real_counters.get_counters(); ///< @todo: filter

	for (auto& [module, balancer] : reals)
	{
		const auto& [module_id, module_name] = module;
		(void)module_id;

		if (filter_module &&
		    module_name != *filter_module)
		{
			continue;
		}

		for (auto& [service_key, service] : balancer)
		{
			const auto& [virtual_ip, proto, virtual_port] = service_key;

			if (filter_virtual_ip &&
			    virtual_ip != *filter_virtual_ip)
			{
				continue;
			}

			if (filter_proto &&
			    proto != *filter_proto)
			{
				continue;
			}

			if (filter_virtual_port &&
			    virtual_port != *filter_virtual_port)
			{
				continue;
			}

			response[module][service_key].swap(service);

			auto& [scheduler, version, response_reals] = response[module][service_key];
			(void)scheduler;
			(void)version;

			std::vector<common::icp::balancer_real_find::real> filtered_reals;
			for (auto& [real_ip, real_port, enabled, weight, connections, packets, bytes] : response_reals)
			{
				(void)connections; ///< @todo: DELETE
				(void)packets;
				(void)bytes;

				if (filter_real_ip &&
				    real_ip != *filter_real_ip)
				{
					continue;
				}

				if (filter_real_port &&
				    real_port != *filter_real_port)
				{
					continue;
				}

				auto it = counters.find({module_name,
				                         {virtual_ip, proto, virtual_port},
				                         {real_ip, real_port}});
				if (it != counters.end())
				{
					filtered_reals.emplace_back(real_ip, real_port, enabled, weight, connections, (it->second)[0], (it->second)[1]);
				}
			}

			filtered_reals.swap(response_reals);
		}
	}

	return response;
}

void balancer_t::balancer_real(const common::icp::balancer_real::request& request)
{
	std::lock_guard<std::mutex> guard(reals_enabled_mutex);
	for (const auto& [module_name, virtual_ip, proto, virtual_port, real_ip, real_port, enable, weight] : request)
	{
		std::tuple<std::string, balancer::service_key_t, balancer::real_key_t> key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

		if (enable)
		{
			reals_enabled[key] = weight;
		}
		else
		{
			reals_enabled.erase(key);
		}
	}
}

void balancer_t::balancer_real_flush()
{
	common::idp::updateGlobalBaseBalancer::request balancer;

	std::lock_guard<std::mutex> guard(config_switch_mutex);

	flush_reals(balancer, generations_config.current());
	dataplane.updateGlobalBaseBalancer(balancer);

	generations_services.next_lock();
	update_service(generations_config.current(), generations_services.next());
	generations_services.switch_generation();
	generations_services.next_unlock();
}

common::icp::balancer_announce::response balancer_t::balancer_announce() const
{
	auto services_current_guard = generations_services.current_lock_guard();
	return generations_services.current().announces;
}

void balancer_t::update_service(const balancer::generation_config_t& generation_config,
				balancer::generation_services_t& generation_services)
{
	for (const auto& [module_name, balancer] : generation_config.config_balancers)
	{
		uint64_t services_reals_enabled_count = 0;
		uint64_t services_reals_count = 0;

		for (const auto& [service_id, virtual_ip, proto, virtual_port, version, scheduler, scheduler_params, forwarding_method, flags, reals] : balancer.services)
		{
			(void) flags;
			(void) scheduler_params;
			(void) forwarding_method;

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				continue;
			}

			uint32_t enabled_count = 0;

			auto& [service_scheduler, service_version, service_connections, service_packets, service_bytes] = generation_services.services[{balancer.balancer_id, module_name}][{virtual_ip, proto, virtual_port}];
			service_scheduler = to_string(scheduler); ///< @todo: OPT
			service_version = version;
			(void)service_connections; ///< @todo: DELETE
			(void)service_packets; ///< filled in request
			(void)service_bytes; ///< filled in request

			auto& [reals_service_scheduler, reals_version, service_reals] = generation_services.reals[{balancer.balancer_id, module_name}][{virtual_ip, proto, virtual_port}];
			reals_service_scheduler = service_scheduler;
			reals_version = version;

			for (const auto& [real_ip, real_port, weight] : reals)
			{
				std::tuple<std::string, balancer::service_key_t, balancer::real_key_t> key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

				services_reals_count++;

				bool enabled = false;
				uint32_t effective_weight = weight;
				{
					std::lock_guard<std::mutex> guard(reals_enabled_mutex);
					auto it = reals_enabled.find(key);
					if (it != reals_enabled.end())
					{
						enabled = true;
						if (it->second.has_value())
						{
							effective_weight = it->second.value();
						}
					}
				}

				if (enabled)
				{
					generation_services.reals_enabled_count++;
					services_reals_enabled_count++;
					enabled_count++;
				}

				service_reals.emplace_back(real_ip,
				                           real_port,
				                           enabled,
				                           effective_weight,
				                           0, ///< @todo: DELETE
				                           0, ///< filled in request
				                           0); ///< filled in request
			}

			if (enabled_count)
			{
				generation_services.announces.emplace(module_name, virtual_ip);
			}
		}

		generation_services.summary.emplace_back(module_name,
		                                         balancer.services.size(),
		                                         services_reals_enabled_count,
		                                         services_reals_count,
		                                         0,
		                                         balancer.next_module);
	}
}


void balancer_t::compile(common::idp::updateGlobalBase::request& globalbase,
                         const balancer::generation_config_t& generation_config)
{
	common::idp::updateGlobalBase::update_balancer_services::request balancer_services;
	auto& [req_services, req_reals, req_binding] = balancer_services;

	for (const auto& [module_name, balancer] : generation_config.config_balancers)
	{
		for (const auto& [service_id, virtual_ip, proto, virtual_port, version, scheduler, scheduler_params, forwarding_method, flags, reals] : balancer.services)
		{
			(void) scheduler_params;
			(void) version;

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				continue;
			}

			const auto real_start = req_reals.size();

			for (const auto& [real_ip, real_port, weight] : reals)
			{
				(void) weight;

				std::tuple<std::string, balancer::service_key_t, balancer::real_key_t> key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

				const auto counter_ids = real_counters.get_ids(key);

				uint32_t real_unordered_id = 0;
				{
					std::lock_guard<std::mutex> guard(reals_unordered_mutex);
					auto it = reals_unordered.find(key);
					if (it != reals_unordered.end())
					{
						real_unordered_id = it->second;
					}
					else
					{
						YANET_LOG_WARNING("where unordered id?\n");
						continue;
					}
				}

				req_reals.emplace_back(common::idp::updateGlobalBase::update_balancer_services::real{
					real_unordered_id,
					real_ip,
					counter_ids[0]});
				req_binding.emplace_back(real_unordered_id);
			}

			const auto counter_ids = service_counters.get_ids({module_name, {virtual_ip, proto, virtual_port}});
			req_services.emplace_back(common::idp::updateGlobalBase::update_balancer_services::service{
				service_id,
				flags,
				counter_ids[0],
			    scheduler,
				forwarding_method,
			    balancer.default_wlc_power, //todo use scheduler_params.wlc_power when other services will be able to set it
				(uint32_t)real_start,
				(uint32_t)(req_reals.size() - real_start)});
		}

	}

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::update_balancer_services,
				common::idp::updateGlobalBase::update_balancer_services::request{req_services,
												 req_reals,
												 req_binding});
}

void balancer_t::flush_reals(common::idp::updateGlobalBaseBalancer::request& balancer,
                         const balancer::generation_config_t& generation_config)
{
	common::idp::updateGlobalBaseBalancer::update_balancer_unordered_real::request balancer_unordered_real_request;

	for (const auto& [module_name, balancer] : generation_config.config_balancers)
	{

		for (const auto& [service_id, virtual_ip, proto, virtual_port, version, scheduler, scheduler_params, forwarding_method, flags, reals] : balancer.services)
		{
			(void)flags;
			(void)scheduler;
			(void)scheduler_params;
			(void)version;
			(void)forwarding_method;

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				continue;
			}

			for (const auto& [real_ip, real_port, weight] : reals)
			{
				std::tuple<std::string, balancer::service_key_t, balancer::real_key_t> key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

				bool enabled = false;
				uint32_t effective_weight = weight;
				{
					std::lock_guard<std::mutex> guard(reals_enabled_mutex);
					auto it = reals_enabled.find(key);
					if (it != reals_enabled.end())
					{
						enabled = true;
						if (it->second.has_value())
						{
							effective_weight = it->second.value();
						}
					}
				}

				uint32_t real_unordered_id = 0;
				{
					std::lock_guard<std::mutex> guard(reals_unordered_mutex);
					auto it = reals_unordered.find(key);
					if (it != reals_unordered.end())
					{
						real_unordered_id = it->second;
					}
					else
					{
						YANET_LOG_WARNING("where unordered id?\n");
						continue;
					}
				}

				balancer_unordered_real_request.emplace_back(real_unordered_id,
				                                             enabled,
				                                             effective_weight);
			}
		}
	}

	balancer.emplace_back(common::idp::updateGlobalBaseBalancer::requestType::update_balancer_unordered_real,
	                      balancer_unordered_real_request);

}

void balancer_t::counters_gc_thread()
{
	while (!flagStop)
	{
		service_counters.gc();
		real_counters.gc();

		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}

void balancer_t::reconfigure_wlc_thread()
{
	while (!flagStop)
	{
		balancer_real_flush();

		std::this_thread::sleep_for(std::chrono::seconds(YANET_CONFIG_BALANCER_WLC_RECONFIGURE));
	}
}
