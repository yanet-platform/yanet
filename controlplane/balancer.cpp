#include <optional>

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

	controlPlane->register_command(common::icp::requestType::balancer_config, [this]() {
		return balancer_config();
	});

	controlPlane->register_command(common::icp::requestType::balancer_summary, [this]() {
		return balancer_summary();
	});

	controlPlane->register_command(common::icp::requestType::balancer_service, [this](const common::icp::request& request) {
		return balancer_service(std::get<common::icp::balancer_service::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::balancer_real_find, [this](const common::icp::request& request) {
		return balancer_real_find(std::get<common::icp::balancer_real_find::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::balancer_real, [this](const common::icp::request& request) {
		return balancer_real(std::get<common::icp::balancer_real::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::balancer_real_flush, [this]() {
		return balancer_real_flush();
	});

	controlPlane->register_command(common::icp::requestType::balancer_announce, [this]() {
		return balancer_announce();
	});

	controlPlane->register_service(this);

	funcThreads.emplace_back([this]() {
		counters_gc_thread();
	});

	funcThreads.emplace_back([this]() {
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
	switch (proto_ipaddr.addr_case())
	{
		case common::icp_proto::IPAddr::AddrCase::kIpv4:
			return common::ipv4_address_t(proto_ipaddr.ipv4());
		case common::icp_proto::IPAddr::AddrCase::kIpv6:
			return common::ipv6_address_t((uint8_t*)proto_ipaddr.ipv6().data());
		default:
			throw std::string("internal error: address type is not set");
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
	                                    req->virtual_port_opt_case() == common::icp_proto::BalancerRealFindRequest::VirtualPortOptCase::kVirtualPort ? std::optional<uint16_t>{req->virtual_port()} : std::nullopt,
	                                    req->has_real_ip() ? std::optional<common::ip_address_t>{convert_to_ip_address(req->real_ip())} : std::nullopt,
	                                    req->real_port_opt_case() == common::icp_proto::BalancerRealFindRequest::RealPortOptCase::kRealPort ? std::optional<uint16_t>{req->real_port()} : std::nullopt});

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

			if (port.has_value())
			{
				proto_service_key->set_port(port.value());
			}

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

				if (port.has_value())
				{
					proto_real->set_port(port.value());
				}

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
	for (const auto& real : req->reals())
	{
		request.emplace_back(real.module(),
		                     convert_to_ip_address(real.virtual_ip()),
		                     real.proto() == common::icp_proto::NetProto::tcp ? IPPROTO_TCP : IPPROTO_UDP,
		                     real.virtual_port_opt_case() == common::icp_proto::BalancerRealRequest_Real::VirtualPortOptCase::kVirtualPort ? std::make_optional(real.virtual_port()) : std::nullopt,
		                     convert_to_ip_address(real.real_ip()),
		                     real.real_port_opt_case() == common::icp_proto::BalancerRealRequest_Real::RealPortOptCase::kRealPort ? std::make_optional(real.real_port()) : std::nullopt,
		                     real.enable(),
		                     real.weight_opt_case() == common::icp_proto::BalancerRealRequest_Real::WeightOptCase::kWeight ? std::make_optional(real.weight()) : std::nullopt);
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
	controlplane_values.emplace_back("balancer.real_counters.size", std::to_string(real_counters.size()));
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
		for (const auto& [service_id,
		                  virtual_ip,
		                  proto,
		                  virtual_port,
		                  version,
		                  scheduler,
		                  scheduler_params,
		                  forwarding_method,
		                  flags,
		                  ipv4_outer_source_network,
		                  ipv6_outer_source_network,
		                  reals] : balancer.services)
		{
			GCC_BUG_UNUSED(service_id);
			GCC_BUG_UNUSED(version);
			GCC_BUG_UNUSED(scheduler);
			GCC_BUG_UNUSED(scheduler_params);
			GCC_BUG_UNUSED(reals);
			GCC_BUG_UNUSED(flags);
			GCC_BUG_UNUSED(forwarding_method);
			GCC_BUG_UNUSED(ipv4_outer_source_network);
			GCC_BUG_UNUSED(ipv6_outer_source_network);

			service_counters.remove({module_name, {virtual_ip, proto, virtual_port}});

			for (const auto& [real_ip, real_port, real_weight] : reals)
			{
				GCC_BUG_UNUSED(real_weight);

				const std::tuple<std::string,
				                 balancer::service_key_t,
				                 balancer::real_key_t>
				        key = {module_name,
				               {virtual_ip, proto, virtual_port},
				               {real_ip, real_port}};

				real_counters.remove(key, base_prev.variables.find("balancer_real_timeout")->second.value);
			}
		}
	}

	for (const auto& [module_name, balancer] : base_next.balancers)
	{
		std::unordered_set<std::tuple<common::ip_address_t, std::optional<uint16_t>, uint8_t>> vip_vport_proto;

		for (const auto& [service_id,
		                  virtual_ip,
		                  proto,
		                  virtual_port,
		                  version,
		                  scheduler,
		                  scheduler_params,
		                  forwarding_method,
		                  flags,
		                  ipv4_outer_source_network,
		                  ipv6_outer_source_network,
		                  reals] : balancer.services)
		{
			GCC_BUG_UNUSED(service_id);
			GCC_BUG_UNUSED(version);
			GCC_BUG_UNUSED(scheduler);
			GCC_BUG_UNUSED(scheduler_params);
			GCC_BUG_UNUSED(flags);
			GCC_BUG_UNUSED(forwarding_method);
			GCC_BUG_UNUSED(ipv4_outer_source_network);
			GCC_BUG_UNUSED(ipv6_outer_source_network);

			service_counters.insert({module_name, {virtual_ip, proto, virtual_port}});

			vip_vport_proto.insert({virtual_ip, virtual_port, proto});

			for (const auto& [real_ip, real_port, real_weight] : reals)
			{
				GCC_BUG_UNUSED(real_weight);

				const std::tuple<std::string,
				                 balancer::service_key_t,
				                 balancer::real_key_t>
				        key = {module_name,
				               {virtual_ip, proto, virtual_port},
				               {real_ip, real_port}};

				real_counters.insert(key);
			}
		}

		dataplane.update_vip_vport_proto({balancer.balancer_id, vip_vport_proto});
	}

	service_counters.allocate();
	real_counters.allocate([&](const auto& key) {
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
	real_counters.release([&](const auto& key) {
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

		{
			std::lock_guard<std::mutex> guard(reals_enabled_mutex);
			/*
			At some point, real_updates and real_reload_updates may contain different sets of real updates,
			depending on the interaction of update, flush and reload operations. In addition to the possibility
			that real_reload_updates is smaller than its counterpart, it should be enough to reset only
			the first of them, and then reset both, since the initial state of real_reload_updates, which already
			contains all the changes, was made immediately before the restart operation began.
			*/
			real_updates = real_reload_updates;
			real_reload_updates.clear();
			in_reload = false;
		}

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
		GCC_BUG_UNUSED(response_services);
		GCC_BUG_UNUSED(response_reals_enabled);
		GCC_BUG_UNUSED(response_reals);
		GCC_BUG_UNUSED(response_next_module);

		auto it = name_id.find(response_module_name);
		if (it == name_id.end())
		{
			continue;
		}

		auto response_module_id = it->second;

		response_connections = 0;
		for (const auto& [socket_id, service_connections] : balancer_service_connections)
		{
			GCC_BUG_UNUSED(socket_id);

			uint32_t socket_connections = 0;
			for (const auto& [key, value] : service_connections)
			{
				const auto& [balancer_id, virtual_ip, proto, virtual_port] = key;
				GCC_BUG_UNUSED(virtual_ip);
				GCC_BUG_UNUSED(proto);
				GCC_BUG_UNUSED(virtual_port);

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
		GCC_BUG_UNUSED(module_id);

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
			GCC_BUG_UNUSED(scheduler);
			GCC_BUG_UNUSED(version);
			GCC_BUG_UNUSED(connections); ///< @todo: DELETE

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
		GCC_BUG_UNUSED(module_id);

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
			GCC_BUG_UNUSED(scheduler);
			GCC_BUG_UNUSED(version);

			std::vector<common::icp::balancer_real_find::real> filtered_reals;
			for (auto& [real_ip, real_port, enabled, weight, connections, packets, bytes] : response_reals)
			{
				GCC_BUG_UNUSED(connections); ///< @todo: DELETE
				GCC_BUG_UNUSED(packets);
				GCC_BUG_UNUSED(bytes);

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
		balancer::real_key_global_t key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

		if (enable)
		{
			reals_enabled[key] = weight;
		}
		else
		{
			reals_enabled.erase(key);
		}

		real_updates.insert(key);

		if (in_reload)
		{
			real_reload_updates.insert(key);
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
	std::lock_guard<std::mutex> guard(reals_enabled_mutex);
	in_reload = true;

	for (const auto& [module_name, balancer] : generation_config.config_balancers)
	{
		uint64_t services_reals_enabled_count = 0;
		uint64_t services_reals_count = 0;

		for (const auto& [service_id,
		                  virtual_ip,
		                  proto,
		                  virtual_port,
		                  version,
		                  scheduler,
		                  scheduler_params,
		                  forwarding_method,
		                  flags,
		                  ipv4_outer_source_network,
		                  ipv6_outer_source_network,
		                  reals] : balancer.services)
		{
			GCC_BUG_UNUSED(flags);
			GCC_BUG_UNUSED(scheduler_params);
			GCC_BUG_UNUSED(forwarding_method);
			GCC_BUG_UNUSED(ipv4_outer_source_network);
			GCC_BUG_UNUSED(ipv6_outer_source_network);

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				continue;
			}

			uint32_t enabled_count = 0;

			auto& [service_scheduler, service_version, service_connections, service_packets, service_bytes] = generation_services.services[{balancer.balancer_id, module_name}][{virtual_ip, proto, virtual_port}];
			service_scheduler = to_string(scheduler); ///< @todo: OPT
			service_version = version;
			GCC_BUG_UNUSED(service_connections); ///< @todo: DELETE
			GCC_BUG_UNUSED(service_packets); ///< filled in request
			GCC_BUG_UNUSED(service_bytes); ///< filled in request

			auto& [reals_service_scheduler, reals_version, service_reals] = generation_services.reals[{balancer.balancer_id, module_name}][{virtual_ip, proto, virtual_port}];
			reals_service_scheduler = service_scheduler;
			reals_version = version;

			for (const auto& [real_ip, real_port, weight] : reals)
			{
				balancer::real_key_global_t key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

				services_reals_count++;

				bool enabled = false;
				uint32_t effective_weight = weight;
				{
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
		for (const auto& [service_id,
		                  virtual_ip,
		                  proto,
		                  virtual_port,
		                  version,
		                  scheduler,
		                  scheduler_params,
		                  forwarding_method,
		                  flags,
		                  ipv4_outer_source_network,
		                  ipv6_outer_source_network,
		                  reals] : balancer.services)
		{
			GCC_BUG_UNUSED(scheduler_params);
			GCC_BUG_UNUSED(version);

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				continue;
			}

			const auto real_start = req_reals.size();

			for (const auto& [real_ip, real_port, weight] : reals)
			{
				GCC_BUG_UNUSED(weight);

				balancer::real_key_global_t key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

				const auto counter_id = real_counters.get_id(key);

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

				req_reals.emplace_back(real_unordered_id, real_ip, counter_id);
				req_binding.emplace_back(real_unordered_id);
			}

			const auto counter_id = service_counters.get_id({module_name, {virtual_ip, proto, virtual_port}});
			req_services.emplace_back(
			        service_id,
			        flags,
			        counter_id,
			        scheduler,
			        forwarding_method,
			        balancer.default_wlc_power, // todo use scheduler_params.wlc_power when other services will be able to set it
			        (uint32_t)real_start,
			        (uint32_t)(req_reals.size() - real_start),
			        ipv4_outer_source_network,
			        ipv6_outer_source_network);
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

	std::lock_guard<std::mutex> guard(reals_enabled_mutex);

	for (const auto& [module_name, balancer] : generation_config.config_balancers)
	{

		for (const auto& [service_id,
		                  virtual_ip,
		                  proto,
		                  virtual_port,
		                  version,
		                  scheduler,
		                  scheduler_params,
		                  forwarding_method,
		                  flags,
		                  ipv4_outer_source_network,
		                  ipv6_outer_source_network,
		                  reals] : balancer.services)
		{
			GCC_BUG_UNUSED(flags);
			GCC_BUG_UNUSED(scheduler);
			GCC_BUG_UNUSED(scheduler_params);
			GCC_BUG_UNUSED(version);
			GCC_BUG_UNUSED(forwarding_method);
			GCC_BUG_UNUSED(ipv4_outer_source_network);
			GCC_BUG_UNUSED(ipv6_outer_source_network);

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				continue;
			}

			for (const auto& [real_ip, real_port, weight] : reals)
			{
				balancer::real_key_global_t key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

				if (real_updates.find(key) == real_updates.end())
				{
					// There is nothing to update as real
					// was not touched after the last one flush
					continue;
				}

				bool enabled = false;
				uint32_t effective_weight = weight;
				if (auto it = reals_enabled.find(key); it != reals_enabled.end())
				{
					enabled = true;
					if (it->second.has_value())
					{
						effective_weight = it->second.value();
					}
				}

				if (auto found_weight = get_effective_weight(reals_wlc_weight, key); found_weight)
				{
					effective_weight = *found_weight;
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

				real_updates.erase(key);
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
		if (balancer_t::reconfigure_wlc())
		{
			balancer_real_flush();
		}

		std::this_thread::sleep_for(std::chrono::seconds(YANET_CONFIG_BALANCER_WLC_RECONFIGURE));
	}
}

bool balancer_t::reconfigure_wlc()
{
	bool wlc_weight_changed = false;

	common::idp::updateGlobalBaseBalancer::request balancer;
	const auto balancer_real_connections = dataplane.balancer_real_connections();

	std::lock_guard<std::mutex> guard(reals_enabled_mutex);

	for (const auto& [module_name, balancer] : generations_config.current().config_balancers)
	{

		for (const auto& [service_id,
		                  virtual_ip,
		                  proto,
		                  virtual_port,
		                  version,
		                  scheduler,
		                  scheduler_params,
		                  forwarding_method,
		                  flags,
		                  ipv4_outer_source_network,
		                  ipv6_outer_source_network,
		                  reals] : balancer.services)
		{
			GCC_BUG_UNUSED(flags);
			GCC_BUG_UNUSED(version);
			GCC_BUG_UNUSED(forwarding_method);
			GCC_BUG_UNUSED(ipv4_outer_source_network);
			GCC_BUG_UNUSED(ipv6_outer_source_network);

			if (scheduler != ::balancer::scheduler::wlc)
			{
				continue;
			}

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				continue;
			}

			std::vector<std::tuple<balancer::real_key_global_t, uint32_t, uint32_t>> service_reals_usage_info;
			uint32_t connection_sum = 0;
			uint32_t weight_sum = 0;

			for (const auto& [real_ip, real_port, weight] : reals)
			{
				balancer::real_key_global_t key = {module_name, {virtual_ip, proto, virtual_port}, {real_ip, real_port}};

				auto weight_found = get_effective_weight(reals_enabled, key);
				uint32_t effective_weight = weight_found ? weight_found.value() : weight;

				weight_sum += effective_weight;

				// don`t count connections for disabled reals - it can make other reals "feel" underloaded
				if (effective_weight == 0)
				{
					continue;
				}

				common::idp::balancer_real_connections::real_key_t real_connections_key = {balancer.balancer_id,
				                                                                           virtual_ip,
				                                                                           proto,
				                                                                           virtual_port.value(),
				                                                                           real_ip,
				                                                                           real_port.value()};
				uint32_t connections = 0;
				for (auto& [socket_id, real_connections] : balancer_real_connections)
				{
					GCC_BUG_UNUSED(socket_id);

					if (auto it = real_connections.find(real_connections_key);
					    it != real_connections.end())
					{
						connections += it->second;
					}
				}

				connection_sum += connections;

				service_reals_usage_info.emplace_back(key,
				                                      effective_weight,
				                                      connections);
			}

			for (auto [key,
			           effective_weight,
			           connections] : service_reals_usage_info)
			{
				uint32_t wlc_power = scheduler_params.wlc_power;
				if (wlc_power < 1 || wlc_power > 100)
				{
					wlc_power = YANET_CONFIG_BALANCER_WLC_DEFAULT_POWER;
				}

				effective_weight = calculate_wlc_weight(effective_weight, connections, weight_sum, connection_sum, wlc_power);

				if (reals_wlc_weight[key] != effective_weight)
				{
					reals_wlc_weight[key] = effective_weight;
					real_updates.insert(key);
					if (in_reload)
					{
						real_reload_updates.insert(key);
					}
					wlc_weight_changed = true;
				}
			}
		}
	}

	return wlc_weight_changed;
}

uint32_t balancer_t::calculate_wlc_weight(uint32_t weight, uint32_t connections, uint32_t weight_sum, uint32_t connection_sum, uint32_t wlc_power)
{
	if (weight == 0 || weight_sum == 0 || connection_sum < weight_sum)
	{
		return weight;
	}

	auto wlc_ratio = std::max(1.0, wlc_power * (1 - 1.0 * connections * weight_sum / connection_sum / weight));
	auto wlc_weight = (uint32_t)(weight * wlc_ratio);

	if (wlc_weight > YANET_CONFIG_BALANCER_REAL_WEIGHT_MAX)
	{
		wlc_weight = YANET_CONFIG_BALANCER_REAL_WEIGHT_MAX;
	}

	return wlc_weight;
}