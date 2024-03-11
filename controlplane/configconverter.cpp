#include <chrono>

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "acl.h"
#include "configconverter.h"
#include "controlplane.h"
#include "errors.h"
#include "isystem.h"

eResult config_converter_t::process(uint32_t serial)
{
	globalbase.clear();
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::clear,
	                        std::tuple<>{});

	baseNext.serial = serial;
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::serial_update,
	                        serial);

	try
	{
		processLogicalPorts();
		processRoutes();
		processDecap();
		processNat64stateful();
		processNat64();
		processNat46clat();
		processTun64();
		processBalancer();
		processDregress();
		processAcl();

		buildAcl();
	}
	catch (const error_result_t& error)
	{
		YANET_LOG_ERROR("%s\n", error.what());

		return error.result();
	}

	return eResult::success;
}

void config_converter_t::convertToFlow(const std::string& nextModule,
                                       common::globalBase::tFlow& flow) const
{
	std::string moduleName;
	std::string entry;

	if (nextModule.find(':') == std::string::npos)
	{
		moduleName = nextModule;
		entry = "";
	}
	else
	{
		moduleName = nextModule.substr(0, nextModule.find(':'));
		entry = nextModule.substr(nextModule.find(':') + 1);
	}

	if (moduleName == "controlPlane")
	{
		flow.type = common::globalBase::eFlowType::controlPlane;
		return;
	}
	else if (moduleName == "drop")
	{
		flow.type = common::globalBase::eFlowType::drop;
		return;
	}
	else if (moduleName == "")
	{
		flow.type = common::globalBase::eFlowType::drop;
		return;
	}

	auto it = baseNext.moduleTypes.find(moduleName);
	if (it == baseNext.moduleTypes.end())
	{
		throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
	}

	const std::string& moduleType = it->second;

	if (moduleType == "logicalPort")
	{
		flow.type = common::globalBase::eFlowType::logicalPort_egress;

		auto it = baseNext.logicalPorts.find(moduleName);
		if (it == baseNext.logicalPorts.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.logicalPortId = it->second.logicalPortId;
	}
	else if (moduleType == "route")
	{
		auto it = baseNext.routes.find(moduleName);
		if (it == baseNext.routes.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		if (entry == "")
		{
			flow.type = common::globalBase::eFlowType::route;
		}
		else if (entry == "local")
		{
			flow.type = common::globalBase::eFlowType::route_local;
		}
		else if (entry == "tunnel")
		{
			flow.type = common::globalBase::eFlowType::route_tunnel;

			if (!it->second.tunnel_enabled)
			{
				throw error_result_t(eResult::invalidFlow, "invalid entry (tunnel not configured)");
			}
		}
		else
		{
			throw error_result_t(eResult::invalidFlow, "invalid entry: " + entry);
		}

		flow.data.routeId = it->second.routeId;
	}
	else if (moduleType == "tun64")
	{
		if (entry == "ipv4_checked")
		{
			flow.type = common::globalBase::eFlowType::tun64_ipv4_checked;
		}
		else if (entry == "ipv6_checked")
		{
			flow.type = common::globalBase::eFlowType::tun64_ipv6_checked;
		}
		else
		{
			throw error_result_t(eResult::invalidFlow, "invalid entry: " + entry);
		}

		auto it = baseNext.tunnels.find(moduleName);
		if (it == baseNext.tunnels.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.tun64Id = it->second.tun64Id;
	}
	else if (moduleType == "decap")
	{
		if (entry == "checked")
		{
			flow.type = common::globalBase::eFlowType::decap_checked;
		}
		else
		{
			throw error_result_t(eResult::invalidFlow, "invalid entry: " + entry);
		}

		auto it = baseNext.decaps.find(moduleName);
		if (it == baseNext.decaps.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.decapId = it->second.decapId;
	}
	else if (moduleType == "nat64stateful")
	{
		if (entry == "lan")
		{
			flow.type = common::globalBase::eFlowType::nat64stateful_lan;
		}
		else if (entry == "wan")
		{
			flow.type = common::globalBase::eFlowType::nat64stateful_wan;
		}
		else
		{
			throw error_result_t(eResult::invalidFlow, "invalid entry: " + entry);
		}

		auto it = baseNext.nat64statefuls.find(moduleName);
		if (it == baseNext.nat64statefuls.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.nat64stateful_id = it->second.nat64stateful_id;
	}
	else if (moduleType == "nat64stateless")
	{
		if (entry == "ingress_checked")
		{
			flow.type = common::globalBase::eFlowType::nat64stateless_ingress_checked;
		}
		else if (entry == "ingress_icmp")
		{
			flow.type = common::globalBase::eFlowType::nat64stateless_ingress_icmp;
		}
		else if (entry == "ingress_fragmentation")
		{
			flow.type = common::globalBase::eFlowType::nat64stateless_ingress_fragmentation;
		}
		else if (entry == "egress_checked")
		{
			flow.type = common::globalBase::eFlowType::nat64stateless_egress_checked;
		}
		else if (entry == "egress_icmp")
		{
			flow.type = common::globalBase::eFlowType::nat64stateless_egress_icmp;
		}
		else if (entry == "egress_fragmentation")
		{
			flow.type = common::globalBase::eFlowType::nat64stateless_egress_fragmentation;
		}
		else if (entry == "egress_farm")
		{
			flow.type = common::globalBase::eFlowType::nat64stateless_egress_farm;
		}
		else
		{
			throw error_result_t(eResult::invalidFlow, "invalid entry: " + entry);
		}

		auto it = baseNext.nat64statelesses.find(moduleName);
		if (it == baseNext.nat64statelesses.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.nat64stateless.id = it->second.nat64statelessId;
	}
	else if (moduleType == "nat46clat")
	{
		if (entry == "lan")
		{
			flow.type = common::globalBase::eFlowType::nat46clat_lan;
		}
		else if (entry == "wan")
		{
			flow.type = common::globalBase::eFlowType::nat46clat_wan;
		}
		else
		{
			throw error_result_t(eResult::invalidFlow, "invalid entry: " + entry);
		}

		auto it = baseNext.nat46clats.find(moduleName);
		if (it == baseNext.nat46clats.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.nat46clat_id = it->second.nat46clat_id;
	}
	else if (moduleType == "acl")
	{
		flow.type = common::globalBase::eFlowType::acl_ingress;

		auto it = baseNext.acls.find(moduleName);
		if (it == baseNext.acls.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.aclId = it->second.aclId;
	}
	else if (moduleType == "dregress")
	{
		flow.type = common::globalBase::eFlowType::dregress;

		auto it = baseNext.dregresses.find(moduleName);
		if (it == baseNext.dregresses.end())
			if (!exist(baseNext.dregresses, moduleName))
			{
				throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
			}

		flow.data.dregressId = it->second.dregressId;
	}
	else if (moduleType == "balancer")
	{
		auto it = baseNext.balancers.find(moduleName);
		if (it == baseNext.balancers.end())
		{
			throw error_result_t(eResult::invalidFlow, "invalid nextModule: " + nextModule);
		}

		flow.data.balancer.id = it->second.balancer_id;

		if (entry == "icmp_reply")
		{
			flow.type = common::globalBase::eFlowType::balancer_icmp_reply;
		}
		else if (entry == "icmp_forward")
		{
			flow.type = common::globalBase::eFlowType::balancer_icmp_forward;
		}
		else if (entry == "fragment")
		{
			flow.type = common::globalBase::eFlowType::balancer_fragment;
		}
		else
		{
			flow.type = common::globalBase::eFlowType::balancer;
		}
	}
	else
	{
		throw error_result_t(eResult::invalidType, "invalid moduleType");
	}
}

common::globalBase::tFlow config_converter_t::convertToFlow(std::string nextModule,
                                                            const std::string& entryName) const
{
	return convertToFlow(nextModule + ":" + entryName);
}

common::globalBase::tFlow config_converter_t::convertToFlow(std::string nextModule) const
{
	common::globalBase::tFlow result;

	convertToFlow(nextModule, result);

	return result;
}

void config_converter_t::processLogicalPorts()
{
	for (auto& [moduleName, logicalPort] : baseNext.logicalPorts)
	{
		(void)moduleName;

		if (logicalPort.logicalPortId >= CONFIG_YADECAP_LOGICALPORTS_SIZE)
		{
			throw error_result_t(eResult::invalidLogicalPortId, "invalid logicalPortId: " + std::to_string(logicalPort.logicalPortId));
		}

		if (logicalPort.vlanId > 0xFFF)
		{
			throw error_result_t(eResult::invalidLogicalPortId, "invalid vlanId: " + std::to_string(logicalPort.vlanId));
		}

		convertToFlow(logicalPort.nextModule, logicalPort.flow);

		if (logicalPort.flow.type != common::globalBase::eFlowType::acl_ingress &&
		    logicalPort.flow.type != common::globalBase::eFlowType::route &&
		    logicalPort.flow.type != common::globalBase::eFlowType::controlPlane &&
		    logicalPort.flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for logical port: " + std::to_string(unsigned(logicalPort.flow.type)));
		}
	}
}

void config_converter_t::serializeLogicalPorts()
{
	for (auto& [moduleName, logicalPort] : baseNext.logicalPorts)
	{
		(void)moduleName;

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::updateLogicalPort,
		                        common::idp::updateGlobalBase::updateLogicalPort::request{logicalPort.logicalPortId,
		                                                                                  logicalPort.physicalPortId,
		                                                                                  logicalPort.vlanId,
		                                                                                  logicalPort.macAddress,
		                                                                                  logicalPort.promiscuousMode,
		                                                                                  logicalPort.flow});
	}
}

void config_converter_t::processRoutes()
{
	for (auto& [module_name, route] : baseNext.routes)
	{
		(void)module_name;

		if (route.routeId >= CONFIG_YADECAP_ROUTES_SIZE)
		{
			throw error_result_t(eResult::invalidId, "invalid routeId: " + std::to_string(route.routeId));
		}

		for (auto& [interface_name, interface] : route.interfaces)
		{
			(void)interface_name;

			if (interface.interfaceId >= CONFIG_YADECAP_INTERFACES_SIZE)
			{
				throw error_result_t(eResult::invalidInterfaceId, "invalid interfaceId: " + std::to_string(interface.interfaceId));
			}

			convertToFlow(interface.nextModule, interface.flow);

			if (interface.flow.type != common::globalBase::eFlowType::logicalPort_egress &&
			    interface.flow.type != common::globalBase::eFlowType::controlPlane &&
			    interface.flow.type != common::globalBase::eFlowType::drop)
			{
				throw error_result_t(eResult::invalidFlow, "invalid flow type for route: " + std::to_string(unsigned(interface.flow.type)));
			}

			interface.aclId = YANET_ACL_ID_UNKNOWN;
			if (!interface.acl.empty())
			{
				auto it = baseNext.acls.find(interface.acl);
				if (it == baseNext.acls.end())
				{
					throw error_result_t(eResult::invalidAclId, "invalid interface acl: " + interface.acl);
				}
				interface.aclId = it->second.aclId;
				interface.flow.type = common::globalBase::eFlowType::acl_egress;
			}
		}
	}
}

void config_converter_t::serializeRoutes()
{
	for (auto& [moduleName, route] : baseNext.routes)
	{
		(void)moduleName;

		std::optional<common::idp::updateGlobalBase::update_route::tunnel> tunnel;
		if (route.tunnel_enabled)
		{
			tunnel = {route.ipv4_source_address,
			          route.ipv6_source_address,
			          route.udp_destination_port};
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::update_route,
		                        common::idp::updateGlobalBase::update_route::request{route.routeId,
		                                                                             tunnel});
	}

	/// continue in route_t::compile()
}

void config_converter_t::processDecap()
{
	for (auto& [moduleName, decap] : baseNext.decaps)
	{
		(void)moduleName;

		if (decap.decapId >= CONFIG_YADECAP_DECAPS_SIZE)
		{
			throw error_result_t(eResult::invalidDecapId, "invalid decapId: " + std::to_string(decap.decapId));
		}

		convertToFlow(decap.nextModule, decap.flow);

		if (decap.flow.type != common::globalBase::eFlowType::route &&
		    decap.flow.type != common::globalBase::eFlowType::route_tunnel &&
		    decap.flow.type != common::globalBase::eFlowType::controlPlane &&
		    decap.flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for decap: " + std::to_string(unsigned(decap.flow.type)));
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::updateDecap,
		                        common::idp::updateGlobalBase::updateDecap::request{decap.decapId,
		                                                                            decap.dscpMarkType,
		                                                                            decap.dscp,
		                                                                            decap.ipv6_enabled,
		                                                                            decap.flow});
	}
}

void config_converter_t::processNat64stateful()
{
	for (auto& [name, nat64stateful] : baseNext.nat64statefuls)
	{
		(void)name;

		if (nat64stateful.nat64stateful_id >= YANET_CONFIG_NAT64STATEFULS_SIZE)
		{
			throw error_result_t(eResult::invalidId, "invalid nat64stateful_id: " + std::to_string(nat64stateful.nat64stateful_id));
		}

		convertToFlow(nat64stateful.next_module, nat64stateful.flow);

		if (nat64stateful.flow.type != common::globalBase::eFlowType::route &&
		    nat64stateful.flow.type != common::globalBase::eFlowType::route_tunnel &&
		    nat64stateful.flow.type != common::globalBase::eFlowType::controlPlane &&
		    nat64stateful.flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for nat64stateful: " + std::string(eFlowType_toString(nat64stateful.flow.type)));
		}
	}

	/// continue in nat64stateful_t::compile()
}

void config_converter_t::processTun64()
{
	for (auto& [moduleName, tunnel] : baseNext.tunnels)
	{
		(void)moduleName;

		if (tunnel.tun64Id >= CONFIG_YADECAP_TUN64_SIZE)
		{
			throw error_result_t(eResult::invalidTun64Id, "invalid Tun64Id: " + std::to_string(tunnel.tun64Id));
		}

		convertToFlow(tunnel.nextModule, tunnel.flow);

		if (tunnel.flow.type != common::globalBase::eFlowType::route &&
		    tunnel.flow.type != common::globalBase::eFlowType::route_tunnel &&
		    tunnel.flow.type != common::globalBase::eFlowType::controlPlane &&
		    tunnel.flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for tun64: " + std::to_string(unsigned(tunnel.flow.type)));
		}
	}
	/// continue in tun64_t::compile()
}

void config_converter_t::processNat64()
{
	for (auto& [moduleName, nat64stateless] : baseNext.nat64statelesses)
	{
		(void)moduleName;

		if (nat64stateless.nat64statelessId >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			throw error_result_t(eResult::invalidNat64statelessId, "invalid nat64statelessId: " + std::to_string(nat64stateless.nat64statelessId));
		}

		convertToFlow(nat64stateless.nextModule, nat64stateless.flow);

		if (nat64stateless.flow.type != common::globalBase::eFlowType::route &&
		    nat64stateless.flow.type != common::globalBase::eFlowType::route_tunnel &&
		    nat64stateless.flow.type != common::globalBase::eFlowType::controlPlane &&
		    nat64stateless.flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for nat64: " + std::to_string(unsigned(nat64stateless.flow.type)));
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::updateNat64stateless,
		                        common::idp::updateGlobalBase::updateNat64stateless::request{nat64stateless.nat64statelessId,
		                                                                                     nat64stateless.dscpMarkType,
		                                                                                     nat64stateless.dscp,
		                                                                                     nat64stateless.firewall,
		                                                                                     nat64stateless.flow,
		                                                                                     nat64stateless.defrag_farm_prefix,
		                                                                                     nat64stateless.defrag_source_prefix,
		                                                                                     nat64stateless.farm});

		for (const auto& [key, value] : nat64stateless.translations)
		{
			const auto& [ipv6Address, ipv6DestinationAddress, ingressPortRange] = key;
			const auto& [ipv4Address, egressPortRange, translationId] = value;

			if (translationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
			{
				throw error_result_t(eResult::invalidConfigurationFile, "too many translations");
			}

			std::optional<std::tuple<uint16_t, uint16_t>> range;

			if (ingressPortRange && egressPortRange)
			{
				range = std::tuple<uint16_t, uint16_t>{ingressPortRange.value().from(),
				                                       egressPortRange.value().from()};
			}

			globalbase.emplace_back(common::idp::updateGlobalBase::requestType::updateNat64statelessTranslation,
			                        common::idp::updateGlobalBase::updateNat64statelessTranslation::request{translationId,
			                                                                                                ipv6Address,
			                                                                                                ipv6DestinationAddress,
			                                                                                                ipv4Address,
			                                                                                                range});
		}
	}
}

void config_converter_t::processNat46clat()
{
	for (auto& [module_name, nat46clat] : baseNext.nat46clats)
	{
		(void)module_name;

		if (nat46clat.nat46clat_id >= YANET_CONFIG_NAT46CLATS_SIZE)
		{
			throw error_result_t(eResult::invalidId, "invalid nat46clat_id: " + std::to_string(nat46clat.nat46clat_id));
		}

		convertToFlow(nat46clat.next_module, nat46clat.flow);

		if (nat46clat.flow.type != common::globalBase::eFlowType::route &&
		    nat46clat.flow.type != common::globalBase::eFlowType::route_tunnel &&
		    nat46clat.flow.type != common::globalBase::eFlowType::controlPlane &&
		    nat46clat.flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for nat46clat: " + std::string(eFlowType_toString(nat46clat.flow.type)));
		}
	}

	/// continue in nat46clat::manager::compile()
}

void config_converter_t::processBalancer()
{
	uint64_t balancer_reals_count = 0;

	for (auto& [moduleName, balancer] : baseNext.balancers)
	{
		(void)moduleName;

		if (balancer.balancer_id >= YANET_CONFIG_BALANCERS_SIZE)
		{
			throw error_result_t(eResult::invalidId, "invalid balancer_id: " + std::to_string(balancer.balancer_id));
		}

		convertToFlow(balancer.next_module, balancer.flow);

		if (balancer.flow.type != common::globalBase::eFlowType::route &&
		    balancer.flow.type != common::globalBase::eFlowType::controlPlane &&
		    balancer.flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for balancer: " + std::to_string(unsigned(balancer.flow.type)));
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::update_balancer,
		                        common::idp::updateGlobalBase::update_balancer::request{balancer.balancer_id,
		                                                                                balancer.source_ipv6,
		                                                                                balancer.source_ipv4,
		                                                                                balancer.flow});

		for (const auto& [service_id,
		                  vip,
		                  proto,
		                  vport,
		                  version,
		                  scheduler,
		                  scheduler_params,
		                  forwarding_method,
		                  flags,
		                  ipv4_outer_source_network,
		                  ipv6_outer_source_network,
		                  reals] : balancer.services)
		{
			/// @todo:
			(void)vip;
			(void)proto;
			(void)vport;
			(void)scheduler;
			(void)scheduler_params;
			(void)flags;
			(void)reals;
			(void)version;
			(void)forwarding_method;
			(void)ipv4_outer_source_network;
			(void)ipv6_outer_source_network;

			if (service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
			{
				throw error_result_t(eResult::invalidConfigurationFile, "too many services");
			}

			if (reals.empty())
			{
				continue;
			}

			balancer_reals_count += reals.size();

			if (balancer_reals_count > YANET_CONFIG_BALANCER_REALS_SIZE)
			{
				throw error_result_t(eResult::invalidConfigurationFile, "too many reals");
			}
		}
	}

	/// continue in balancer_t::compile()
}

void config_converter_t::processDregress()
{
	for (auto& [moduleName, dregress] : baseNext.dregresses)
	{
		(void)moduleName;

		if (dregress.dregressId >= CONFIG_YADECAP_DREGRESS_SIZE)
		{
			throw error_result_t(eResult::invalidId, "invalid dregressId: " + std::to_string(dregress.dregressId));
		}

		common::globalBase::tFlow flow;
		convertToFlow(dregress.nextModule, flow);

		if (flow.type != common::globalBase::eFlowType::route &&
		    flow.type != common::globalBase::eFlowType::controlPlane &&
		    flow.type != common::globalBase::eFlowType::drop)
		{
			throw error_result_t(eResult::invalidFlow, "invalid flow type for dregress: " + std::to_string(unsigned(flow.type)));
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::updateDregress,
		                        common::idp::updateGlobalBase::updateDregress::request{dregress.dregressId,
		                                                                               dregress.ipv4SourceAddress,
		                                                                               dregress.ipv6SourceAddress,
		                                                                               dregress.udpDestinationPort,
		                                                                               dregress.onlyLongest,
		                                                                               flow});
	}
}

void config_converter_t::processAcl()
{
	for (auto& [moduleName, acl] : baseNext.acls)
	{
		(void)moduleName;

		if (acl.synchronization)
		{
			for (const auto& logicalPort : acl.synchronization->logicalPorts)
			{
				if (!exist(baseNext.logicalPorts, logicalPort))
				{
					throw error_result_t(eResult::invalidConfigurationFile, std::string("logical port ") + logicalPort + " is required for FW synchronization, but not described");
				}
			}
		}

		if (acl.aclId >= CONFIG_YADECAP_ACLS_SIZE)
		{
			throw error_result_t(eResult::invalidAclId, "invalid aclId: " + std::to_string(acl.aclId));
		}

		if ((!acl.src4_early_decap.empty() && !acl.dst4_early_decap.empty()) || (!acl.src6_early_decap.empty() && !acl.dst6_early_decap.empty()))
		{
			acl_rules_early_decap(acl);
		}

		for (const auto& nextModule : acl.nextModules)
		{
			const std::string nextModuleName = nextModule.substr(0, nextModule.find(':'));
			const std::string entry = nextModule.substr(nextModule.find(':') + 1);

			auto it = baseNext.moduleTypes.find(nextModuleName);
			if (it == baseNext.moduleTypes.end())
			{
				throw error_result_t(eResult::invalidFlow, "invalid nextModuleName: " + nextModuleName);
			}

			const auto& type = it->second;
			if (type == "route")
			{
				if (entry == "local")
				{
					acl_rules_route_local(acl, nextModuleName);
				}
				else if (entry == "forward")
				{
					acl_rules_route_forward(acl, nextModule);
				}
				else if (entry == "tunnel")
				{
					acl_rules_route_forward(acl, nextModule);
				}
				else
				{
					acl_rules_route_local(acl, nextModule);
					acl_rules_route_forward(acl, nextModule);
				}
			}
			else if (type == "tun64")
			{
				acl_rules_tun64(acl, nextModule);
			}
			else if (type == "decap")
			{
				acl_rules_decap(acl, nextModule);
			}
			else if (type == "nat64stateful")
			{
				acl_rules_nat64stateful(acl, nextModuleName);
			}
			else if (type == "nat64stateless")
			{
				acl_rules_nat64stateless(acl, nextModuleName, entry);
			}
			else if (type == "nat46clat")
			{
				acl_rules_nat46clat(acl, nextModuleName);
			}
			else if (type == "dregress")
			{
				acl_rules_dregress(acl, nextModule);
			}
			else if (type == "balancer")
			{
				acl_rules_balancer(acl, nextModule);
				acl_rules_balancer_icmp_reply(acl, nextModule);
				acl_rules_balancer_icmp_forward(acl, nextModule);
			}
			else
			{
				throw error_result_t(eResult::invalidType, "invalid nextModuleName: " + nextModuleName);
			}
		}

		{
			common::globalBase::tFlow flow = convertToFlow("drop");
			acl.nextModuleRules.emplace_back(flow);
		}
	}
}

void config_converter_t::acl_rules_early_decap(controlplane::base::acl_t& acl) const
{
	common::globalBase::tFlow flow;
	flow.type = common::globalBase::eFlowType::after_early_decap;

	flow.data.aclId = acl.aclId; // should remain in the same acl module for the next step (now for decap packet)

	{
		controlplane::base::acl_rule_network_ipv4_t rule_network(acl.src4_early_decap,
		                                                         acl.dst4_early_decap);

		controlplane::base::acl_rule_transport_other_t rule_transport;
		rule_transport.protocolTypes.insert(IPPROTO_IPIP);
		rule_transport.protocolTypes.insert(IPPROTO_IPV6);

		controlplane::base::acl_rule_t rule = {rule_network,
		                                       controlplane::base::acl_rule_t::fragState::notFragmented,
		                                       rule_transport,
		                                       flow};

		acl.nextModuleRules.emplace_back(rule);
	}

	{
		controlplane::base::acl_rule_network_ipv6_t rule_network(acl.src6_early_decap,
		                                                         acl.dst6_early_decap);

		controlplane::base::acl_rule_transport_other_t rule_transport;
		rule_transport.protocolTypes.insert(IPPROTO_IPIP);
		rule_transport.protocolTypes.insert(IPPROTO_IPV6);

		controlplane::base::acl_rule_t rule = {rule_network,
		                                       controlplane::base::acl_rule_t::fragState::notFragmented,
		                                       rule_transport,
		                                       flow};

		acl.nextModuleRules.emplace_back(rule);
	}
}

void config_converter_t::acl_rules_route_local(controlplane::base::acl_t& acl,
                                               const std::string& next_module) const
{
	common::globalBase::tFlow flow_local = convertToFlow(next_module, "local");

	controlplane::base::acl_rule_network_ipv4_t rule_network_ipv4({common::ipv4_prefix_default},
	                                                              {});

	controlplane::base::acl_rule_network_ipv6_t rule_network_ipv6({common::ipv6_prefix_default},
	                                                              {});

	const auto& route = baseNext.routes.at(next_module);

	for (const auto& [interfaceName, interface] : route.interfaces)
	{
		(void)interfaceName;

		for (const auto& ipAddress : interface.ip_prefixes)
		{
			if (ipAddress.is_ipv4())
			{
				rule_network_ipv4.destinationPrefixes.emplace(ipAddress.address());
			}
			else
			{
				rule_network_ipv6.destinationPrefixes.emplace(ipAddress.address());
			}
		}
	}

	acl.nextModuleRules.emplace_back(rule_network_ipv4, flow_local);
	acl.nextModuleRules.emplace_back(rule_network_ipv6, flow_local);
}

void config_converter_t::acl_rules_route_forward(controlplane::base::acl_t& acl,
                                                 const std::string& next_module) const
{
	(void)next_module;

	common::globalBase::tFlow flow = convertToFlow(next_module);
	acl.nextModuleRules.emplace_back(flow);
}

void config_converter_t::acl_rules_tun64(controlplane::base::acl_t& acl,
                                         const std::string& nextModule) const
{
	const auto& tunnel = baseNext.tunnels.at(nextModule);
	std::set<common::ipv4_prefix_t> ipv4_prefixes;
	std::set<common::ipv6_prefix_t> ipv6_prefixes;

	for (const auto& prefix : tunnel.prefixes)
	{
		if (prefix.is_ipv4())
		{
			ipv4_prefixes.emplace(prefix);
		}
		else
		{
			ipv6_prefixes.emplace(prefix);
		}
	}

	{ /// from any IPv4 to tun64 prefixes
		auto flow = convertToFlow(nextModule, "ipv4_checked");
		controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default},
		                                                         ipv4_prefixes);
		controlplane::base::acl_rule_t rule = {rule_network, flow};
		acl.nextModuleRules.emplace_back(rule);
	}
	{ /// from any IPv6 and proto IPIP to tunnel's source address
		auto flow = convertToFlow(nextModule, "ipv6_checked");
		controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default},
		                                                         ipv6_prefixes);
		controlplane::base::acl_rule_transport_other_t rule_transport{IPPROTO_IPIP};
		controlplane::base::acl_rule_t rule = {rule_network, rule_transport, flow};
		rule.fragment = {controlplane::base::acl_rule_t::fragState::notFragmented};
		acl.nextModuleRules.emplace_back(rule);
	}
}

void config_converter_t::acl_rules_decap(controlplane::base::acl_t& acl,
                                         const std::string& nextModule) const
{
	common::globalBase::tFlow flow;
	convertToFlow(nextModule + ":checked", flow);

	const auto& decap = baseNext.decaps.at(nextModule);

	{
		controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default},
		                                                         decap.prefixes());

		{
			controlplane::base::acl_rule_transport_other_t rule_transport{IPPROTO_IPIP};
			controlplane::base::acl_rule_t rule = {rule_network, rule_transport, flow};
			rule.fragment = {controlplane::base::acl_rule_t::fragState::notFragmented};
			acl.nextModuleRules.emplace_back(rule);
		}

		{
			controlplane::base::acl_rule_transport_other_t rule_transport{IPPROTO_GRE};
			controlplane::base::acl_rule_t rule = {rule_network, rule_transport, flow};
			rule.fragment = {controlplane::base::acl_rule_t::fragState::notFragmented};
			acl.nextModuleRules.emplace_back(rule);
		}

		if (decap.ipv6_enabled)
		{
			controlplane::base::acl_rule_transport_other_t rule_transport{IPPROTO_IPV6};
			controlplane::base::acl_rule_t rule = {rule_network, rule_transport, flow};
			rule.fragment = {controlplane::base::acl_rule_t::fragState::notFragmented};
			acl.nextModuleRules.emplace_back(rule);
		}
	}
}

void config_converter_t::acl_rules_nat64stateful(controlplane::base::acl_t& acl,
                                                 const std::string& next_module) const
{
	const auto& nat64stateful = baseNext.nat64statefuls.at(next_module);

	std::set<common::ipv6_prefix_t> ipv6_prefixes;
	for (const auto& ipv6_prefix : nat64stateful.ipv6_prefixes)
	{
		ipv6_prefixes.emplace(ipv6_prefix);
	}

	std::set<common::ipv4_prefix_t> ipv4_prefixes;
	for (const auto& ipv4_prefix : nat64stateful.ipv4_prefixes)
	{
		ipv4_prefixes.emplace(ipv4_prefix);
	}

	/// fragment
	{
		using fragState = controlplane::base::acl_rule_t::fragState;

		auto flow_drop = convertToFlow("drop"); ///< @todo: reassembly flow

		/// ipv6
		{
			controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default}, ipv6_prefixes);

			controlplane::base::acl_rule_t rule(rule_network, flow_drop);
			rule.fragment = {fragState::firstFragment, fragState::notFirstFragment};

			acl.nextModuleRules.emplace_back(rule);
		}

		/// ipv4
		{
			controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default}, ipv4_prefixes);

			controlplane::base::acl_rule_t rule(rule_network, flow_drop);
			rule.fragment = {fragState::firstFragment, fragState::notFirstFragment};

			acl.nextModuleRules.emplace_back(rule);
		}
	}

	/// lan (ipv6 -> ipv4)
	{
		auto flow = convertToFlow(next_module, "lan");

		controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default}, ipv6_prefixes);

		acl.nextModuleRules.emplace_back(rule_network,
		                                 controlplane::acl_rule_transport_tcp_any,
		                                 flow);

		acl.nextModuleRules.emplace_back(rule_network,
		                                 controlplane::acl_rule_transport_udp_any,
		                                 flow);

		acl.nextModuleRules.emplace_back(rule_network,
		                                 controlplane::base::acl_rule_transport_icmpv6_t(ICMP6_ECHO_REQUEST),
		                                 flow);
	}

	/// wan (ipv4 -> ipv6)
	{
		auto flow = convertToFlow(next_module, "wan");

		controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default}, ipv4_prefixes);

		acl.nextModuleRules.emplace_back(rule_network,
		                                 controlplane::acl_rule_transport_tcp_any,
		                                 flow);

		acl.nextModuleRules.emplace_back(rule_network,
		                                 controlplane::acl_rule_transport_udp_any,
		                                 flow);

		acl.nextModuleRules.emplace_back(rule_network,
		                                 controlplane::base::acl_rule_transport_icmpv4_t(ICMP_ECHOREPLY),
		                                 flow);
	}

	/// other
	{
		auto flow_drop = convertToFlow("drop");

		/// ipv6
		{
			controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default}, ipv6_prefixes);
			acl.nextModuleRules.emplace_back(rule_network, flow_drop);
		}

		/// ipv4
		{
			controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default}, ipv4_prefixes);
			acl.nextModuleRules.emplace_back(rule_network, flow_drop);
		}
	}
}

void config_converter_t::acl_rules_nat64stateless(controlplane::base::acl_t& acl,
                                                  const std::string& nextModule,
                                                  const std::string& entry) const
{
	if (entry == "ingress")
	{
		acl_rules_nat64stateless_ingress(acl, nextModule);
	}
	else if (entry == "egress")
	{
		acl_rules_nat64stateless_egress(acl, nextModule);
	}
	else
	{
		acl_rules_nat64stateless_ingress(acl, nextModule);
		acl_rules_nat64stateless_egress(acl, nextModule);
	}
}

/// @todo: move
using fragState = controlplane::base::acl_rule_t::fragState;

void config_converter_t::acl_rules_nat64stateless_ingress(controlplane::base::acl_t& acl,
                                                          const std::string& nextModule) const
{
	const auto& nat64stateless = baseNext.nat64statelesses.at(nextModule);

	auto flow = convertToFlow(nextModule, "ingress_checked");

	auto flow_icmp = convertToFlow(nextModule, "ingress_icmp");

	auto flow_fragmentation = convertToFlow(nextModule, "ingress_fragmentation");

	auto flow_drop = convertToFlow("drop");

	for (const auto& [key, value] : nat64stateless.translations)
	{
		const auto& [ipv6Address, ipv6DestinationAddress, ingressPortRange] = key;
		const auto& [ipv4Address, egressPortRange, translationId] = value;

		(void)ipv4Address;
		(void)egressPortRange;

		flow.data.nat64stateless.translationId = translationId;
		flow_icmp.data.nat64stateless.translationId = translationId;
		flow_fragmentation.data.nat64stateless.translationId = translationId;

		controlplane::base::acl_rule_network_ipv6_t rule_network({{ipv6Address, 128}},
		                                                         {{ipv6DestinationAddress, 96}});

		if (!ingressPortRange)
		{
			/// 1:1

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{values_t{ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow_icmp);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{values_t{ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::firstFragment, rule_transport, flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFirstFragment, rule_transport, flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
			}

			acl.nextModuleRules.emplace_back(rule_network, flow);
		}
		else
		{
			/// N:1 (port range)

			{
				controlplane::base::acl_rule_transport_tcp_t rule_transport{ingressPortRange.value(),
				                                                            range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_udp_t rule_transport{ingressPortRange.value(),
				                                                            range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{ICMP6_ECHO_REQUEST,
				                                                               range_t{0x00, 0xFF},
				                                                               ingressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}

			/* @todo
			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               ingressPortRange};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}
			*/

			acl.nextModuleRules.emplace_back(rule_network,
			                                 fragState::notFirstFragment,
			                                 flow_fragmentation);

			///

			{
				controlplane::base::acl_rule_transport_tcp_t rule_transport{ingressPortRange.value(),
				                                                            range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_udp_t rule_transport{ingressPortRange.value(),
				                                                            range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{ICMP6_ECHO_REQUEST,
				                                                               range_t{0x00, 0xFF},
				                                                               ingressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               ingressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow_icmp);
			}

			{
				controlplane::base::acl_rule_transport_icmpv6_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               ingressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
			}
		}
	}
}

void config_converter_t::acl_rules_nat64stateless_egress(controlplane::base::acl_t& acl,
                                                         const std::string& nextModule) const
{
	const auto& nat64stateless = baseNext.nat64statelesses.at(nextModule);

	auto flow = convertToFlow(nextModule, "egress_checked");

	auto flow_icmp = convertToFlow(nextModule, "egress_icmp");

	auto flow_fragmentation = convertToFlow(nextModule, "egress_fragmentation");

	auto flow_drop = convertToFlow("drop");

	if (nat64stateless.farm)
	{
		auto flow_farm = convertToFlow(nextModule, "egress_farm");

		controlplane::base::acl_rule_network_ipv6_t rule_network({{nat64stateless.defrag_source_prefix.value(), 96}},
		                                                         {{nat64stateless.defrag_farm_prefix.value(), 96}});
		acl.nextModuleRules.emplace_back(rule_network, flow_farm);
	}

	for (const auto& [key, value] : nat64stateless.translations)
	{
		(void)key;

		const auto& [ipv4Address, egressPortRange, translationId] = value;

		flow.data.nat64stateless.translationId = translationId;
		flow_icmp.data.nat64stateless.translationId = translationId;
		flow_fragmentation.data.nat64stateless.translationId = translationId;

		controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default},
		                                                         {{ipv4Address, 32}});

		if (!egressPortRange)
		{
			/// 1:1

			if (nat64stateless.firewall)
			{
				{
					controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            range_t{0x0000, 0xFFFF}};
					rule_transport.flags = {TCP_SYN_FLAG, TCP_ACK_FLAG};
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            range_t{0x0000, 0xFFFF}};
					rule_transport.flags = {0, TCP_SYN_FLAG | TCP_FIN_FLAG | TCP_ACK_FLAG | TCP_PSH_FLAG | TCP_RST_FLAG | TCP_URG_FLAG};
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            range_t{0x0000, 0xFFFF}};
					rule_transport.flags = {TCP_FIN_FLAG | TCP_PSH_FLAG | TCP_URG_FLAG, 0};
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_udp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            range_t{0x0000, 0xFFFF}};
					rule_transport.sourcePorts.remove(53);
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
					                                                               range_t{0x00, 0xFF},
					                                                               range_t{0x0000, 0xFFFF}};
					rule_transport.types.remove(ICMP_ECHOREPLY);
					rule_transport.types.remove(ICMP_ECHO);
					rule_transport.types.remove(ICMP_DEST_UNREACH);
					rule_transport.types.remove(ICMP_TIME_EXCEEDED);
					rule_transport.types.remove(ICMP_PARAMETERPROB);
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_other_t rule_transport{range_t{0x00, 0xFF}};
					rule_transport.protocolTypes.remove(IPPROTO_TCP);
					rule_transport.protocolTypes.remove(IPPROTO_UDP);
					rule_transport.protocolTypes.remove(IPPROTO_ICMP);
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{values_t{ICMP_ECHO, ICMP_ECHOREPLY},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow_icmp);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{values_t{ICMP_ECHO, ICMP_ECHOREPLY},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::firstFragment, rule_transport, flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFirstFragment, rule_transport, flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               range_t{0x0000, 0xFFFF}};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
			}

			acl.nextModuleRules.emplace_back(rule_network, flow);
		}
		else
		{
			/// N:1 (port range)

			if (nat64stateless.firewall)
			{
				{
					controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            egressPortRange.value()};
					rule_transport.flags = {TCP_SYN_FLAG, TCP_ACK_FLAG};
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            egressPortRange.value()};
					rule_transport.flags = {0, TCP_SYN_FLAG | TCP_FIN_FLAG | TCP_ACK_FLAG | TCP_PSH_FLAG | TCP_RST_FLAG | TCP_URG_FLAG};
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            egressPortRange.value()};
					rule_transport.flags = {TCP_FIN_FLAG | TCP_PSH_FLAG | TCP_URG_FLAG, 0};
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_udp_t rule_transport{range_t{0x0000, 0xFFFF},
					                                                            egressPortRange.value()};
					rule_transport.sourcePorts.remove(53);
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}

				{
					controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
					                                                               range_t{0x00, 0xFF},
					                                                               egressPortRange.value()};
					rule_transport.types.remove(ICMP_ECHOREPLY);
					rule_transport.types.remove(ICMP_ECHO);
					rule_transport.types.remove(ICMP_DEST_UNREACH);
					rule_transport.types.remove(ICMP_TIME_EXCEEDED);
					rule_transport.types.remove(ICMP_PARAMETERPROB);
					acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
				}
			}

			///

			{
				controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_udp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{ICMP_ECHOREPLY,
				                                                               range_t{0x00, 0xFF},
				                                                               egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}

			/* @todo
			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               egressPortRange};
				acl.nextModuleRules.emplace_back(rule_network,
				                                 fragState::firstFragment,
				                                 rule_transport,
				                                 flow_fragmentation);
			}
			*/

			acl.nextModuleRules.emplace_back(rule_network,
			                                 fragState::notFirstFragment,
			                                 flow_fragmentation);

			///

			{
				controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_udp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{ICMP_ECHOREPLY,
				                                                               range_t{0x00, 0xFF},
				                                                               egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow_icmp);
			}

			{
				controlplane::base::acl_rule_transport_icmpv4_t rule_transport{range_t{0x00, 0xFF},
				                                                               range_t{0x00, 0xFF},
				                                                               egressPortRange.value()};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
			}
		}
	}
}

void config_converter_t::acl_rules_nat46clat(controlplane::base::acl_t& acl,
                                             const std::string& next_module) const
{
	const auto& nat46clat = baseNext.nat46clats.at(next_module);

	std::set<common::ipv6_prefix_t> ipv6_prefixes;
	for (const auto& ipv6_prefix : nat46clat.ipv6_prefixes)
	{
		ipv6_prefixes.emplace(ipv6_prefix);
	}

	std::set<common::ipv4_prefix_t> ipv4_prefixes;
	for (const auto& ipv4_prefix : nat46clat.ipv4_prefixes)
	{
		ipv4_prefixes.emplace(ipv4_prefix);
	}

	auto flow_drop = convertToFlow("drop");

	/// lan (ipv4 -> ipv6)
	{
		auto flow = convertToFlow(next_module, "lan");
		controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default}, ipv4_prefixes);

		{
			controlplane::base::acl_rule_transport_icmpv4_t rule_transport(values_t(ICMP_ECHO, ICMP_ECHOREPLY),
			                                                               range_t(0x00, 0xFF),
			                                                               range_t(0x0000, 0xFFFF));
			acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow);
		}

		{
			controlplane::base::acl_rule_transport_icmpv4_t rule_transport;
			acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
		}

		acl.nextModuleRules.emplace_back(rule_network, flow);
	}

	/// wan (ipv6 -> ipv4)
	{
		auto flow = convertToFlow(next_module, "wan");
		controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default}, ipv6_prefixes);

		{
			controlplane::base::acl_rule_transport_icmpv6_t rule_transport(values_t(ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY),
			                                                               range_t(0x00, 0xFF),
			                                                               range_t(0x0000, 0xFFFF));
			acl.nextModuleRules.emplace_back(rule_network, fragState::notFragmented, rule_transport, flow);
		}

		{
			controlplane::base::acl_rule_transport_icmpv6_t rule_transport;
			acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow_drop);
		}

		acl.nextModuleRules.emplace_back(rule_network, flow);
	}
}

void config_converter_t::acl_rules_dregress(controlplane::base::acl_t& acl,
                                            const std::string& nextModule) const
{
	auto flow = convertToFlow(nextModule, "checked");

	const auto& dregress = baseNext.dregresses.at(nextModule);

	for (const auto& ipv6SourcePrefix : dregress.ipv6SourcePrefixes)
	{
		controlplane::base::acl_rule_network_ipv6_t rule_network({ipv6SourcePrefix}, {dregress.ipv6DestinationPrefix});

		{
			controlplane::base::acl_rule_transport_other_t rule_transport(values_t(IPPROTO_IPIP, IPPROTO_IPV6));
			controlplane::base::acl_rule_t rule = {rule_network, rule_transport, flow};
			rule.fragment = {controlplane::base::acl_rule_t::fragState::notFragmented};
			acl.nextModuleRules.emplace_back(rule);
		}
	}
}

void config_converter_t::acl_rules_balancer(controlplane::base::acl_t& acl,
                                            const std::string& nextModule) const
{
	const auto& balancer = baseNext.balancers.at(nextModule);

	auto flow = convertToFlow(nextModule);
	auto flow_fragment = convertToFlow(nextModule, "fragment"); ///< actually drop

	for (const auto& [service_id,
	                  vip,
	                  proto,
	                  vport,
	                  version,
	                  scheduler,
	                  scheduler_params,
	                  forwarding_method,
	                  flags,
	                  ipv4_outer_source_network,
	                  ipv6_outer_source_network,
	                  reals] : balancer.services)
	{
		(void)scheduler;
		(void)scheduler_params;
		(void)version;
		(void)flags;
		(void)forwarding_method;
		(void)ipv4_outer_source_network;
		(void)ipv6_outer_source_network;

		if (reals.empty())
		{
			continue;
		}

		flow.data.balancer.service_id = service_id;

		if (vip.is_ipv4())
		{
			controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default},
			                                                         {{vip.get_ipv4(), 32}});

			{
				controlplane::base::acl_rule_t rule(rule_network, flow_fragment);
				rule.fragment = {fragState::firstFragment, fragState::notFirstFragment};
				acl.nextModuleRules.emplace_back(rule);
			}

			if (proto == IPPROTO_TCP)
			{
				controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            vport};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}
			else if (proto == IPPROTO_UDP)
			{
				controlplane::base::acl_rule_transport_udp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            vport};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}
			else
			{
				/// @todo
			}
		}
		else
		{
			controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default},
			                                                         {{vip.get_ipv6(), 128}});

			{
				controlplane::base::acl_rule_t rule(rule_network, flow_fragment);
				rule.fragment = {fragState::firstFragment, fragState::notFirstFragment};
				acl.nextModuleRules.emplace_back(rule);
			}

			if (proto == IPPROTO_TCP)
			{
				controlplane::base::acl_rule_transport_tcp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            vport};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}
			else if (proto == IPPROTO_UDP)
			{
				controlplane::base::acl_rule_transport_udp_t rule_transport{range_t{0x0000, 0xFFFF},
				                                                            vport};
				acl.nextModuleRules.emplace_back(rule_network, rule_transport, flow);
			}
			else
			{
				/// @todo
			}
		}
	}
}

void config_converter_t::acl_rules_balancer_icmp_reply(controlplane::base::acl_t& acl,
                                                       const std::string& nextModule) const
{
	const auto& balancer = baseNext.balancers.at(nextModule);

	auto flow = convertToFlow(nextModule, "icmp_reply");

	for (const auto& [service_id,
	                  vip,
	                  proto,
	                  vport,
	                  version,
	                  scheduler,
	                  scheduler_params,
	                  forwarding_method,
	                  flags,
	                  ipv4_outer_source_network,
	                  ipv6_outer_source_network,
	                  reals] : balancer.services)
	{
		(void)scheduler;
		(void)scheduler_params;
		(void)flags;
		(void)proto;
		(void)vport;
		(void)version;
		(void)forwarding_method;
		(void)ipv4_outer_source_network;
		(void)ipv6_outer_source_network;

		if (reals.empty())
		{
			continue;
		}

		flow.data.balancer.service_id = service_id;
		/// @todo: flow_fragmentation.data.balancer.service_id = service_id;

		if (vip.is_ipv4())
		{
			controlplane::base::acl_rule_network_ipv4_t rule_network({common::ipv4_prefix_default},
			                                                         {{vip.get_ipv4(), 32}});

			ranges_t ping_types(values_t({ICMP_ECHO})); // echo request should be handled by balancer (it will prepare reply)
			ranges_t ping_codes(range_t(0x00, 0xFF));

			controlplane::base::acl_rule_transport_icmpv4_t rule_ping(ping_types, ping_codes);
			acl.nextModuleRules.emplace_back(rule_network, rule_ping, flow);
		}
		else
		{
			controlplane::base::acl_rule_network_ipv6_t rule_network({common::ipv6_prefix_default},
			                                                         {{vip.get_ipv6(), 128}});

			ranges_t ping_ipv6_types(values_t({ICMP6_ECHO_REQUEST})); // echo request should be handled by balancer (it will prepare reply)
			ranges_t ping_ipv6_codes(range_t(0x00, 0xFF));

			controlplane::base::acl_rule_transport_icmpv6_t rule_ping_ipv6(ping_ipv6_types, ping_ipv6_codes);
			acl.nextModuleRules.emplace_back(rule_network, rule_ping_ipv6, flow);
		}
	}
}

void config_converter_t::acl_rules_balancer_icmp_forward(controlplane::base::acl_t& acl,
                                                         const std::string& nextModule) const
{
	const auto& balancer = baseNext.balancers.at(nextModule);

	auto flow = convertToFlow(nextModule, "icmp_forward");

	ranges_t icmpv4_forward_types(values_t({ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, ICMP_REDIRECT, ICMP_SOURCE_QUENCH, ICMP_PARAMETERPROB}));
	controlplane::base::acl_rule_transport_icmpv4_t rule_icmpv4_forward(icmpv4_forward_types);

	ranges_t icmpv6_forward_types(values_t({ICMP6_DST_UNREACH, ICMP6_TIME_EXCEEDED, ICMP6_PARAM_PROB, ICMP6_PACKET_TOO_BIG}));
	controlplane::base::acl_rule_transport_icmpv6_t rule_icmpv6_forward(icmpv6_forward_types);

	for (const auto& [service_id,
	                  vip,
	                  proto,
	                  vport,
	                  version,
	                  scheduler,
	                  scheduler_params,
	                  forwarding_method,
	                  flags,
	                  ipv4_outer_source_network,
	                  ipv6_outer_source_network,
	                  reals] : balancer.services)
	{
		(void)scheduler;
		(void)scheduler_params;
		(void)flags;
		(void)proto;
		(void)vport;
		(void)version;
		(void)forwarding_method;
		(void)ipv4_outer_source_network;
		(void)ipv6_outer_source_network;

		if (reals.empty())
		{
			continue;
		}

		flow.data.balancer.service_id = service_id;
		/// @todo: flow_fragmentation.data.balancer.service_id = service_id;

		if (vip.is_ipv4())
		{
			controlplane::base::acl_rule_network_ipv4_t rule_vip_dst({common::ipv4_prefix_default},
			                                                         {{vip.get_ipv4(), 32}});

			acl.nextModuleRules.emplace_back(rule_vip_dst, rule_icmpv4_forward, flow);
		}
		else
		{
			controlplane::base::acl_rule_network_ipv6_t rule_vip_dst({common::ipv6_prefix_default},
			                                                         {{vip.get_ipv6(), 128}});

			acl.nextModuleRules.emplace_back(rule_vip_dst, rule_icmpv6_forward, flow);
		}
	}
}

std::string config_converter_t::checkLimit(size_t count, const std::string& name, size_t multiplier(size_t))
{
	uint64_t limit = 0;
	for (const auto& [limit_name, socket_id, current, maximum] : limits)
	{
		(void)socket_id;
		(void)current;

		if (limit_name == name)
		{
			limit = multiplier(maximum);
		}
	}

	if (count > limit)
	{
		return std::string("overflow of ") + name + ", limit " + std::to_string(limit) + ", count " + std::to_string(count) + "\n";
	}

	return {};
}

void config_converter_t::buildAcl()
{
	const auto now = std::chrono::steady_clock::now();

	acl::result_t result; ///< @todo: move to class

	auto iface_map = acl::ifaceMapping(baseNext.logicalPorts, baseNext.routes);
	try
	{
		acl::compile(baseNext.acls,
		             iface_map,
		             result);
	}
	catch (...)
	{
		throw error_result_t(eResult::invalidConfigurationFile, "can not compile acls");
	}

	YANET_LOG_INFO("ACL compilation finished in %.3f ms\n",
	               std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - now).count());

	baseNext.iface_map = iface_map;
	for (const auto& [name, aclId] : result.in_iface_map)
	{
		baseNext.logicalPorts[name].flow.data.aclId = aclId;
		baseNext.result_iface_map[aclId].emplace(true, name);
	}

	for (auto& [route_name, route] : baseNext.routes)
	{
		(void)route_name;
		for (auto& [name, iface] : route.interfaces)
		{
			(void)name;
			auto it = result.out_iface_map.find(iface.nextModule);
			if (it != result.out_iface_map.end())
			{
				iface.aclId = it->second;
				baseNext.result_iface_map[iface.aclId].emplace(false, iface.nextModule);
			}
		}
	}

	serializeLogicalPorts();
	serializeRoutes();

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_network_ipv4_source, std::move(result.acl_network_ipv4_source));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_network_ipv4_destination, std::move(result.acl_network_ipv4_destination));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_network_ipv6_source, std::move(result.acl_network_ipv6_source));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_network_ipv6_destination_ht, std::move(result.acl_network_ipv6_destination_ht));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_network_ipv6_destination, std::move(result.acl_network_ipv6_destination));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_network_table, std::move(result.acl_network_table));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_network_flags, std::move(result.acl_network_flags));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_transport_layers, std::move(result.acl_transport_layers));

	{
		if (result.acl_transport_tables.size() != 1)
		{
			throw std::runtime_error("support multithread here");
		}
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_transport_table, std::move(result.acl_transport_tables[0]));
	}

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_total_table, std::move(result.acl_total_table));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::acl_values, std::move(result.acl_values));
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::dump_tags_ids, std::move(result.dump_id_to_tag));

	common::idp::updateGlobalBase::fwstate_synchronization_update::request fwstate_sync_request;
	for (const auto& [moduleName, acl] : baseNext.acls)
	{
		(void)moduleName;

		if (acl.synchronization)
		{
			std::vector<common::globalBase::tFlow> fwstate_synchronization_flows;
			for (const auto& logicalPort : acl.synchronization->logicalPorts)
			{
				fwstate_synchronization_flows.emplace_back(convertToFlow(logicalPort));
			}

			for (auto aclId : result.acl_map[acl.aclId])
			{
				fwstate_sync_request.emplace_back(
				        aclId,
				        acl.synchronization->ipv6SourceAddress,
				        acl.synchronization->multicastIpv6Address,
				        acl.synchronization->unicastIpv6SourceAddress,
				        acl.synchronization->unicastIpv6Address,
				        acl.synchronization->multicastDestinationPort,
				        acl.synchronization->unicastDestinationPort,
				        fwstate_synchronization_flows,
				        convertToFlow(acl.synchronization->ingressNextModule));
			}
		}
	}

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::fwstate_synchronization_update,
	                        fwstate_sync_request);

	common::idp::updateGlobalBase::update_early_decap_flags::request early_decap_flags_request = false;
	for (const auto& [moduleName, acl] : baseNext.acls)
	{
		(void)moduleName;

		// if at least one acl module has early_decap config section, early_decap feature is globally switched on
		if ((!acl.src4_early_decap.empty() && !acl.dst4_early_decap.empty()) || (!acl.src6_early_decap.empty() && !acl.dst6_early_decap.empty()))
		{
			early_decap_flags_request = true;
			break;
		}
	}

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::early_decap_flags,
	                        early_decap_flags_request);

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::sampler_update, baseNext.storeSamples);

	baseNext.ids_map = std::move(result.ids_map);
	baseNext.rules = std::move(result.rules);
	baseNext.dispatcher = std::move(result.dispatcher);
	baseNext.dump_id_to_tag = std::move(result.dump_id_to_tag);
}
