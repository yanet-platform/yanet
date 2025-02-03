#pragma once

#include "cli/helper.h"
#include "common/icontrolplane.h"
#include "common/idataplane.h"
#include "common/iproto_controlplane.h"
#include "common/type.h"

#include "table_printer.h"

namespace balancer
{

void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.balancer_summary();

	FillAndPrintTable({"module",
	                   "services",
	                   "reals_enabled",
	                   "reals",
	                   "connections",
	                   "next_module"},
	                  response);
}

void service(std::string module_string,
             std::optional<common::ip_address_t> virtual_ip,
             std::optional<std::string> proto_string,
             std::optional<std::string> virtual_port_string)
{
	std::optional<std::string> module;
	if (module_string != "" &&
	    module_string != "any")
	{
		module = module_string;
	}

	std::optional<uint16_t> virtual_port;
	if (virtual_port_string)
	{
		virtual_port = std::stoull(*virtual_port_string, nullptr, 0);
	}

	std::optional<uint8_t> proto;
	if (proto_string)
	{
		proto = controlplane::balancer::to_proto(*proto_string);
	}

	interface::controlPlane controlplane;
	const auto response = controlplane.balancer_service({module, virtual_ip, proto, virtual_port});

	interface::dataPlane dataplane;
	auto balancer_service_connections = dataplane.balancer_service_connections();

	TablePrinter table;
	table.insert_row("module",
	                 "virtual_ip",
	                 "proto",
	                 "virtual_port",
	                 "scheduler",
	                 "connections",
	                 "packets",
	                 "bytes",
	                 "version");

	for (const auto& [module, services] : response)
	{
		const auto& [module_id, module_name] = module;

		for (const auto& [service_key, service_value] : services)
		{
			const auto& [virtual_ip, proto, virtual_port] = service_key;
			const auto& [scheduler, version, nap_connections, packets, bytes] = service_value;
			GCC_BUG_UNUSED(nap_connections); ///< @todo: DELETE

			auto proto_string = controlplane::balancer::from_proto(proto);

			common::idp::balancer_service_connections::service_key_t key = {module_id,
			                                                                virtual_ip,
			                                                                proto,
			                                                                virtual_port};

			uint32_t connections = 0;
			for (auto& [socket_id, service_connections] : balancer_service_connections)
			{
				GCC_BUG_UNUSED(socket_id);

				const auto& socket_connections = service_connections[key].value;
				if (socket_connections > connections)
				{
					connections = socket_connections;
				}
			}

			table.insert_row(module_name,
			                 virtual_ip,
			                 proto_string,
			                 virtual_port,
			                 scheduler,
			                 connections,
			                 packets,
			                 bytes,
			                 version);
		}
	}

	table.Print();
}

inline void setip(common::icp_proto::IPAddr* pAddr, const common::ip_address_t& value)
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

void real_find(std::string module_string,
               std::optional<common::ip_address_t> virtual_ip,
               std::optional<std::string> proto_string,
               std::optional<std::string> virtual_port_string,
               std::optional<common::ip_address_t> real_ip,
               std::optional<std::string> real_port_string)
{
	common::icp_proto::BalancerRealFindRequest request;
	if (module_string != "" &&
	    module_string != "any")
	{
		request.set_module(module_string.data());
	}

	if (virtual_ip)
	{
		setip(request.mutable_virtual_ip(), virtual_ip.value());
	}
	if (real_ip)
	{
		setip(request.mutable_real_ip(), real_ip.value());
	}

	if (virtual_port_string)
	{
		request.set_virtual_port(std::stoull(*virtual_port_string, nullptr, 0));
	}

	if (proto_string)
	{
		if (proto_string == "tcp")
		{
			request.set_proto(::common::icp_proto::NetProto::tcp);
		}
		else if (proto_string == "udp")
		{
			request.set_proto(::common::icp_proto::NetProto::udp);
		}
		else
		{
			YANET_LOG_WARNING("undefined net protocol requested: %s", proto_string->c_str());
		}
	}

	if (real_port_string)
	{
		request.set_real_port(std::stoull(*real_port_string, nullptr, 0));
	}

	interface::protoControlPlane controlPlane;
	auto response = controlPlane.balancer_real_find(request);

	interface::dataPlane dataplane;
	auto balancer_real_connections = dataplane.balancer_real_connections();

	TablePrinter table;
	table.insert_row("module",
	                 "virtual_ip",
	                 "proto",
	                 "virtual_port",
	                 "scheduler",
	                 "real_ip",
	                 "real_port",
	                 "enabled",
	                 "weight",
	                 "connections",
	                 "packets",
	                 "bytes",
	                 "version");

	for (const auto& balancer : response.balancers())
	{
		for (const auto& service : balancer.services())
		{
			auto virtual_ip = convert_to_ip_address(service.key().ip());
			auto proto = service.key().proto() == common::icp_proto::NetProto::tcp ? IPPROTO_TCP : IPPROTO_UDP;

			auto proto_string = common::icp_proto::NetProto_descriptor()->value(service.key().proto())->name();

			for (const auto& real : service.reals())
			{
				auto real_ip = convert_to_ip_address(real.ip());
				common::idp::balancer_real_connections::real_key_t key = {(balancer_id_t)balancer.balancer_id(),
				                                                          virtual_ip,
				                                                          proto,
				                                                          service.key().port(),
				                                                          real_ip,
				                                                          real.port()};

				uint32_t connections = 0;
				for (auto& [socket_id, real_connections] : balancer_real_connections)
				{
					GCC_BUG_UNUSED(socket_id);

					const auto& socket_connections = real_connections[key].value;
					if (socket_connections > connections)
					{
						connections = socket_connections;
					}
				}

				table.insert_row(balancer.module(),
				                 virtual_ip,
				                 proto_string,
				                 service.key().port_opt_case() == common::icp_proto::BalancerRealFindResponse_ServiceKey::PortOptCase::kPort ? std::make_optional(service.key().port()) : std::nullopt,
				                 service.scheduler(),
				                 real_ip,
				                 real.port_opt_case() == common::icp_proto::BalancerRealFindResponse_Real::PortOptCase::kPort ? std::make_optional(real.port()) : std::nullopt,
				                 real.enabled(),
				                 real.weight(),
				                 connections,
				                 real.packets(),
				                 real.bytes(),
				                 service.version_opt_case() == common::icp_proto::BalancerRealFindResponse_Service::VersionOptCase::kVersion ? std::make_optional(service.version()) : std::nullopt);
			}
		}
	}

	table.Print();
}

void state(std::string module,
           std::optional<common::ip_address_t> virtual_ip,
           std::optional<std::string> proto_string,
           std::optional<uint16_t> virtual_port,
           std::optional<common::ip_address_t> real_ip,
           std::optional<uint16_t> real_port)
{
	interface::controlPlane controlplane;
	auto config = controlplane.balancer_config();

	std::optional<balancer_id_t> balancer_id;
	if (module != "" &&
	    module != "any")
	{
		if (exist(config, module))
		{
			balancer_id = config[module].balancer_id;
		}
		else
		{
			throw std::string("unknown module: '" + module + "'");
		}
	}

	std::map<balancer_id_t, std::string> modules;
	for (const auto& [module, balancer] : config)
	{
		modules[balancer.balancer_id] = module;
	}

	std::optional<uint8_t> proto;
	if (proto_string)
	{
		proto = controlplane::balancer::to_proto(*proto_string);
	}

	interface::dataPlane dataplane;
	const auto response = dataplane.balancer_connection({balancer_id, virtual_ip, proto, virtual_port, real_ip, real_port});

	std::map<balancer_id_t,
	         std::map<std::tuple<common::ip_address_t, ///< virtual_ip
	                             uint8_t, ///< proto
	                             std::optional<uint16_t>>, ///< virtual_port
	                  std::map<common::idp::balancer_connection::real_key,
	                           std::map<std::tuple<common::ip_address_t, ///< client_ip
	                                               std::optional<uint16_t>>, ///< client_port
	                                    std::tuple<uint32_t, ///< timestamp_create
	                                               uint16_t>>>>>
	        total_connections; ///< timestamp_last_packet

	/// @todo: OPT
	for (const auto& [socket_id, services_real_connections] : response)
	{
		GCC_BUG_UNUSED(socket_id);

		for (const auto& [services_real, connections] : services_real_connections)
		{
			const auto& [balancer_id, virtual_ip, proto, virtual_port, real_key] = services_real;

			auto& map = total_connections[balancer_id][{virtual_ip, proto, virtual_port}][real_key];

			for (const auto& [client_ip, client_port, timestamp_create, timestamp_last_packet, timestamp_gc] : connections)
			{
				GCC_BUG_UNUSED(timestamp_gc);

				auto it = map.find({client_ip, client_port});
				if (it != map.end())
				{
					auto& [map_timestamp_create, map_timestamp_last_packet] = it->second;
					if (timestamp_last_packet > map_timestamp_last_packet)
					{
						map_timestamp_create = timestamp_create;
						map_timestamp_last_packet = timestamp_last_packet;
					}
				}
				else
				{
					map[{client_ip, client_port}] = {timestamp_create, timestamp_last_packet};
				}
			}
		}
	}

	TablePrinter table;
	table.insert_row("module",
	                 "virtual_ip",
	                 "proto",
	                 "virtual_port",
	                 "real_ip",
	                 "real_port",
	                 "client_ip",
	                 "client_port",
	                 "created",
	                 "last_seen");

	uint32_t current_time = time(nullptr);

	for (const auto& [balancer_id, services] : total_connections)
	{
		std::string module = "unknown";
		if (exist(modules, balancer_id))
		{
			module = modules[balancer_id];
		}

		for (const auto& [service_key, reals] : services)
		{
			const auto& [virtual_ip, proto, virtual_port] = service_key;

			auto proto_string = controlplane::balancer::from_proto(proto);

			for (const auto& [real_key, client_socket_id_timestamps] : reals)
			{
				const auto& [real_ip, real_port] = real_key;

				for (const auto& [key, value] : client_socket_id_timestamps)
				{
					const auto& [client_ip, client_port] = key;
					const auto& [timestamp_create, timestamp_last_packet] = value;

					table.insert_row(module,
					                 virtual_ip,
					                 proto_string,
					                 virtual_port,
					                 real_ip,
					                 real_port,
					                 client_ip,
					                 client_port,
					                 (uint32_t)current_time - timestamp_create,
					                 (uint16_t)current_time - timestamp_last_packet);
				}
			}
		}
	}

	table.Print();
}

namespace real
{

void change_state(const std::string& module,
                  const common::ip_address_t& virtual_ip,
                  const std::string& proto,
                  const std::optional<uint16_t>& virtual_port,
                  const common::ip_address_t& real_ip,
                  const std::optional<uint16_t>& real_port,
                  const bool enable,
                  std::optional<uint32_t> weight)
{
	common::icp_proto::BalancerRealRequest request;
	auto* real = request.add_reals();
	real->set_module(module.data());
	setip(real->mutable_virtual_ip(), virtual_ip);
	if (proto == "tcp")
	{
		real->set_proto(::common::icp_proto::NetProto::tcp);
	}
	else if (proto == "udp")
	{
		real->set_proto(::common::icp_proto::NetProto::udp);
	}
	else
	{
		YANET_LOG_WARNING("undefined net protocol requested: %s", proto.c_str());
	}

	setip(real->mutable_real_ip(), real_ip);
	if (virtual_port.has_value())
	{
		real->set_virtual_port(virtual_port.value());
	}
	if (real_port.has_value())
	{
		real->set_real_port(real_port.value());
	}

	real->set_enable(enable);

	if (weight)
	{
		real->set_weight(weight.value());
	}

	interface::protoControlPlane controlPlane;
	controlPlane.balancer_real(request);
}

void enable(const std::string& module,
            const common::ip_address_t& virtual_ip,
            const std::string& proto,
            const std::optional<uint16_t>& virtual_port,
            const common::ip_address_t& real_ip,
            const std::optional<uint16_t>& real_port,
            std::optional<uint32_t> weight)
{
	change_state(module, virtual_ip, proto, virtual_port, real_ip, real_port, true, weight);
}

void disable(const std::string& module,
             const common::ip_address_t& virtual_ip,
             const std::string& proto,
             const std::optional<uint16_t>& virtual_port,
             const common::ip_address_t& real_ip,
             const std::optional<uint16_t>& real_port)
{
	change_state(module, virtual_ip, proto, virtual_port, real_ip, real_port, false, std::nullopt);
}

void flush()
{
	interface::protoControlPlane controlPlane;
	controlPlane.balancer_real_flush();
}

}

void announce()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.balancer_announce();

	FillAndPrintTable({"module", "announces"}, response);
}

}
