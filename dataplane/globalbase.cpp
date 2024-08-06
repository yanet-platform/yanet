#include <memory.h>

#include <rte_errno.h>

#include "common.h"
#include "dataplane.h"
#include "globalbase.h"
#include "worker.h"

#include "common/counters.h"
#include "common/define.h"

#include "debug_latch.h"

using namespace dataplane::globalBase;

atomic::atomic(cDataPlane* dataPlane,
               const tSocketId& socketId) :
        dataPlane(dataPlane),
        socketId(socketId)
{
	fw_state_config.tcp_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_timeout;
	fw_state_config.udp_timeout = dataPlane->getConfigValues().stateful_firewall_udp_timeout;
	fw_state_config.other_protocols_timeout = dataPlane->getConfigValues().stateful_firewall_other_protocols_timeout;
	fw_state_config.sync_timeout = 8;

	memset(physicalPort_flags, 0, sizeof(physicalPort_flags));
	memset(counter_shifts, 0, sizeof(counter_shifts));
	memset(gc_counter_shifts, 0, sizeof(gc_counter_shifts));

	tsc_active_state = dataPlane->getConfigValues().tsc_active_state;
}

atomic::~atomic()
{
}

generation::generation(cDataPlane* dataPlane,
                       const tSocketId& socketId) :
        dataPlane(dataPlane),
        socketId(socketId)
{
	std::fill(balancer_service_ring.ranges,
	          balancer_service_ring.ranges + YANET_CONFIG_BALANCER_SERVICES_SIZE,
	          balancer_service_range_t());

	std::fill(balancer_real_states,
	          balancer_real_states + YANET_CONFIG_BALANCER_REALS_SIZE,
	          balancer_real_state_t());
}

generation::~generation()
{
}

eResult generation::init()
{
	eResult result = eResult::success;

	{
		updater.acl.network_ipv4_source = std::make_unique<acl::network_ipv4_source>("acl.network.v4.source.lpm",
		                                                                             &dataPlane->memory_manager,
		                                                                             socketId);
		result = updater.acl.network_ipv4_source->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.network.ipv4.source = updater.acl.network_ipv4_source->pointer;
	}

	{
		updater.acl.network_ipv4_destination = std::make_unique<acl::network_ipv4_destination>("acl.network.v4.destination.lpm",
		                                                                                       &dataPlane->memory_manager,
		                                                                                       socketId);
		result = updater.acl.network_ipv4_destination->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.network.ipv4.destination = updater.acl.network_ipv4_destination->pointer;
	}

	{
		updater.acl.network_ipv6_source = std::make_unique<acl::network_ipv6_source>("acl.network.v6.source.lpm",
		                                                                             &dataPlane->memory_manager,
		                                                                             socketId);
		result = updater.acl.network_ipv6_source->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.network.ipv6.source = updater.acl.network_ipv6_source->pointer;
	}

	{
		updater.acl.network_ipv6_destination_ht = std::make_unique<acl::network_ipv6_destination_ht>("acl.network.v6.destination.ht",
		                                                                                             &dataPlane->memory_manager,
		                                                                                             socketId);
		result = updater.acl.network_ipv6_destination_ht->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.network.ipv6.destination_ht = updater.acl.network_ipv6_destination_ht->pointer;
	}

	{
		updater.acl.network_ipv6_destination = std::make_unique<acl::network_ipv6_destination>("acl.network.v6.destination.lpm",
		                                                                                       &dataPlane->memory_manager,
		                                                                                       socketId);
		result = updater.acl.network_ipv6_destination->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.network.ipv6.destination = updater.acl.network_ipv6_destination->pointer;
	}

	{
		updater.acl.network_table = std::make_unique<acl::network_table>("acl.network.ht",
		                                                                 &dataPlane->memory_manager,
		                                                                 socketId);
		result = updater.acl.network_table->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.network_table = updater.acl.network_table->pointer;
	}

	{
		updater.acl.transport_layers = std::make_unique<acl::transport_layers>("acl.transport.layers",
		                                                                       &dataPlane->memory_manager,
		                                                                       socketId);
		result = updater.acl.transport_layers->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.transport_layers = updater.acl.transport_layers->pointer;
	}

	acl.transport_layers_mask = 0;

	{
		updater.acl.transport_table = std::make_unique<acl::transport_table>("acl.transport.ht",
		                                                                     &dataPlane->memory_manager,
		                                                                     socketId);
		result = updater.acl.transport_table->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.transport_table = updater.acl.transport_table->pointer;
	}

	{
		updater.acl.total_table = std::make_unique<acl::total_table>("acl.total.ht",
		                                                             &dataPlane->memory_manager,
		                                                             socketId);
		result = updater.acl.total_table->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.total_table = updater.acl.total_table->pointer;
	}

	{
		updater.acl.values = std::make_unique<acl::values>("acl.values",
		                                                   &dataPlane->memory_manager,
		                                                   socketId);
		result = updater.acl.values->init();
		if (result != eResult::success)
		{
			return result;
		}

		acl.values = updater.acl.values->pointer;
	}

	{
		updater.route_lpm4 = std::make_unique<updater_lpm4_24bit_8bit>("route.v4.lpm",
		                                                               &dataPlane->memory_manager,
		                                                               socketId);
		result = updater.route_lpm4->init();
		if (result != eResult::success)
		{
			return result;
		}

		route_lpm4 = updater.route_lpm4->pointer();
	}

	{
		updater.route_lpm6 = std::make_unique<updater_lpm6_8x16bit>("route.v6.lpm",
		                                                            &dataPlane->memory_manager,
		                                                            socketId);
		result = updater.route_lpm6->init();
		if (result != eResult::success)
		{
			return result;
		}

		route_lpm6 = updater.route_lpm6->pointer();
	}

	{
		updater.route_tunnel_lpm4 = std::make_unique<updater_lpm4_24bit_8bit>("route.tunnel.v4.lpm",
		                                                                      &dataPlane->memory_manager,
		                                                                      socketId);
		result = updater.route_tunnel_lpm4->init();
		if (result != eResult::success)
		{
			return result;
		}

		route_tunnel_lpm4 = updater.route_tunnel_lpm4->pointer();
	}

	{
		updater.route_tunnel_lpm6 = std::make_unique<updater_lpm6_8x16bit>("route.tunnel.v6.lpm",
		                                                                   &dataPlane->memory_manager,
		                                                                   socketId);
		result = updater.route_tunnel_lpm6->init();
		if (result != eResult::success)
		{
			return result;
		}

		route_tunnel_lpm6 = updater.route_tunnel_lpm6->pointer();
	}

	return result;
}

eResult generation::update(const common::idp::updateGlobalBase::request& request)
{
	eResult result = eResult::success;

	for (const auto& iter : request)
	{
		const auto& type = std::get<0>(iter);
		const auto& data = std::get<1>(iter);

		YADECAP_LOG_DEBUG("running update of type %d\n", (int)type);

		if (type == common::idp::updateGlobalBase::requestType::clear)
		{
			result = clear();
		}
		else if (type == common::idp::updateGlobalBase::requestType::updateLogicalPort)
		{
			result = updateLogicalPort(std::get<common::idp::updateGlobalBase::updateLogicalPort::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::updateDecap)
		{
			result = updateDecap(std::get<common::idp::updateGlobalBase::updateDecap::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::updateDregress)
		{
			result = updateDregress(std::get<common::idp::updateGlobalBase::updateDregress::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::update_route)
		{
			result = update_route(std::get<common::idp::updateGlobalBase::update_route::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::updateInterface)
		{
			result = updateInterface(std::get<common::idp::updateGlobalBase::updateInterface::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::nat64stateful_update)
		{
			result = nat64stateful_update(std::get<common::idp::updateGlobalBase::nat64stateful_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::nat64stateful_pool_update)
		{
			result = nat64stateful_pool_update(std::get<common::idp::updateGlobalBase::nat64stateful_pool_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::updateNat64stateless)
		{
			result = updateNat64stateless(std::get<common::idp::updateGlobalBase::updateNat64stateless::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::updateNat64statelessTranslation)
		{
			result = updateNat64statelessTranslation(std::get<common::idp::updateGlobalBase::updateNat64statelessTranslation::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::nat46clat_update)
		{
			result = nat46clat_update(std::get<common::idp::updateGlobalBase::nat46clat_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::update_balancer)
		{
			result = update_balancer(std::get<common::idp::updateGlobalBase::update_balancer::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::update_balancer_services)
		{
			result = update_balancer_services(std::get<common::idp::updateGlobalBase::update_balancer_services::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::route_lpm_update)
		{
			result = route_lpm_update(std::get<common::idp::updateGlobalBase::route_lpm_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::route_value_update)
		{
			result = route_value_update(std::get<common::idp::updateGlobalBase::route_value_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::route_tunnel_lpm_update)
		{
			result = route_tunnel_lpm_update(std::get<common::idp::updateGlobalBase::route_tunnel_lpm_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::route_tunnel_weight_update)
		{
			result = route_tunnel_weight_update(std::get<common::idp::updateGlobalBase::route_tunnel_weight_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::route_tunnel_value_update)
		{
			result = route_tunnel_value_update(std::get<common::idp::updateGlobalBase::route_tunnel_value_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::early_decap_flags)
		{
			result = update_early_decap_flags(std::get<common::idp::updateGlobalBase::update_early_decap_flags::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_network_ipv4_source)
		{
			result = acl_network_ipv4_source(std::get<common::idp::updateGlobalBase::acl_network_ipv4_source::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_network_ipv4_destination)
		{
			result = acl_network_ipv4_destination(std::get<common::idp::updateGlobalBase::acl_network_ipv4_destination::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_network_ipv6_source)
		{
			result = acl_network_ipv6_source(std::get<common::idp::updateGlobalBase::acl_network_ipv6_source::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_network_ipv6_destination_ht)
		{
			result = acl_network_ipv6_destination_ht(std::get<common::idp::updateGlobalBase::acl_network_ipv6_destination_ht::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_network_ipv6_destination)
		{
			result = acl_network_ipv6_destination(std::get<common::idp::updateGlobalBase::acl_network_ipv6_destination::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_network_table)
		{
			result = acl_network_table(std::get<common::idp::updateGlobalBase::acl_network_table::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_network_flags)
		{
			result = acl_network_flags(std::get<common::idp::updateGlobalBase::acl_network_flags::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_transport_layers)
		{
			result = acl_transport_layers(std::get<common::idp::updateGlobalBase::acl_transport_layers::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_transport_table)
		{
			result = acl_transport_table(std::get<common::idp::updateGlobalBase::acl_transport_table::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_total_table)
		{
			result = acl_total_table(std::get<common::idp::updateGlobalBase::acl_total_table::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::acl_values)
		{
			result = acl_values(std::get<common::idp::updateGlobalBase::acl_values::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::dump_tags_ids)
		{
			result = dump_tags_ids(std::get<common::idp::updateGlobalBase::dump_tags_ids::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::dregress_prefix_update)
		{
			result = dregress_prefix_update(std::get<common::idp::updateGlobalBase::dregress_prefix_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::dregress_prefix_remove)
		{
			result = dregress_prefix_remove(std::get<common::idp::updateGlobalBase::dregress_prefix_remove::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::dregress_prefix_clear)
		{
			result = dregress_prefix_clear();
		}
		else if (type == common::idp::updateGlobalBase::requestType::dregress_local_prefix_update)
		{
			result = dregress_local_prefix_update(std::get<common::idp::updateGlobalBase::dregress_local_prefix_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::dregress_neighbor_update)
		{
			/// @deprecated
		}
		else if (type == common::idp::updateGlobalBase::requestType::dregress_value_update)
		{
			result = dregress_value_update(std::get<common::idp::updateGlobalBase::dregress_value_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::fwstate_synchronization_update)
		{
			result = fwstate_synchronization_update(std::get<common::idp::updateGlobalBase::fwstate_synchronization_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::sampler_update)
		{
			result = eResult::success;
			sampler_enabled = std::get<common::idp::updateGlobalBase::sampler_update::request>(data);
		}
		else if (type == common::idp::updateGlobalBase::requestType::tun64_update)
		{
			result = tun64_update(std::get<common::idp::updateGlobalBase::tun64_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::tun64mappings_update)
		{
			result = tun64mappings_update(std::get<common::idp::updateGlobalBase::tun64mappings_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::serial_update)
		{
			result = eResult::success;
			serial = std::get<common::idp::updateGlobalBase::serial_update::request>(data);
		}
		else if (type == common::idp::updateGlobalBase::requestType::tsc_state_update)
		{
			result = tsc_state_update(std::get<common::idp::updateGlobalBase::tsc_state_update::request>(data));
		}
		else if (type == common::idp::updateGlobalBase::requestType::tscs_base_value_update)
		{
			result = tscs_base_value_update(std::get<common::idp::updateGlobalBase::tscs_base_value_update::request>(data));
		}
		else
		{
			YADECAP_LOG_ERROR("invalid request type\n");
			return eResult::invalidType;
		}
		YADECAP_LOG_DEBUG("done update of type %d %i\n", (int)type, result != eResult::success ? 0 : 1);

		if (result != eResult::success)
		{
			return result;
		}
	}
	YADECAP_LOG_DEBUG("done update %i\n", result != eResult::success ? 0 : 1);

	return result;
}

eResult generation::updateBalancer(const common::idp::updateGlobalBaseBalancer::request& request)
{
	eResult result = eResult::success;

	for (const auto& iter : request)
	{
		const auto& type = std::get<0>(iter);
		const auto& data = std::get<1>(iter);

		YADECAP_LOG_DEBUG("running update of type %d\n", (int)type);

		if (type == common::idp::updateGlobalBaseBalancer::requestType::update_balancer_unordered_real)
		{
			result = update_balancer_unordered_real(std::get<common::idp::updateGlobalBaseBalancer::update_balancer_unordered_real::request>(data));
		}
		else
		{
			YADECAP_LOG_ERROR("invalid request type\n");
			return eResult::invalidType;
		}

		if (result != eResult::success)
		{
			return result;
		}
	}

	return result;
}

std::array<uint8_t, 6> convert(const rte_ether_addr& from)
{
	std::array<uint8_t, 6> to;
	memcpy(to.data(), from.addr_bytes, 6);
	return to;
}

std::array<uint8_t, 16> convert(const in6_addr& from)
{
	std::array<uint8_t, 16> to;
	memcpy(to.data(), from.__in6_u.__u6_addr8, 16);
	return to;
}

eResult generation::get(const common::idp::getGlobalBase::request& request,
                        common::idp::getGlobalBase::globalBase& globalBaseResponse) const
{
	for (const auto& logicalPortId : std::get<0>(request))
	{
		if (logicalPortId >= CONFIG_YADECAP_LOGICALPORTS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid logicalPortId: '%u'\n", logicalPortId);
			return eResult::invalidLogicalPortId;
		}

		const auto& logicalPort = logicalPorts[logicalPortId];

		std::get<0>(globalBaseResponse)[logicalPortId] = {logicalPort.portId,
		                                                  rte_be_to_cpu_16(logicalPort.vlanId),
		                                                  convert(logicalPort.etherAddress),
		                                                  logicalPort.flow};
	}

	for (const auto& decapId : std::get<1>(request))
	{
		if (decapId >= CONFIG_YADECAP_DECAPS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid decapId: '%u'\n", decapId);
			return eResult::invalidDecapId;
		}

		const auto& decap = decaps[decapId];

		std::get<1>(globalBaseResponse)[decapId] = {decap.flow};
	}

	/** @todo
	for (const auto& interfaceId : std::get<2>(request))
	{
	        if (interfaceId >= CONFIG_YADECAP_INTERFACES_SIZE)
	        {
	                YADECAP_LOG_ERROR("invalid interfaceId: '%u'\n", interfaceId);
	                return eResult::invalidInterfaceId;
	        }

	        const auto& interface = interfaces[interfaceId];

	        std::get<2>(globalBaseResponse)[interfaceId] = {convert(interface.neighborEtherAddress),
	                                                        interface.flow};
	}
	*/

	/// @todo: nat64stateful
	/// @todo: nat64stateless

	return eResult::success;
}

eResult generation::clear()
{
	for (unsigned int logicalPortId = 0;
	     logicalPortId < CONFIG_YADECAP_LOGICALPORTS_SIZE;
	     logicalPortId++)
	{
		logicalPorts[logicalPortId] = dataplane::globalBase::tLogicalPort();
	}

	for (tun64_id_t tun64Id = 0;
	     tun64Id < CONFIG_YADECAP_TUN64_SIZE;
	     tun64Id++)
	{
		tun64tunnels[tun64Id] = dataplane::globalBase::tun64_t();
	}

	for (unsigned int decapId = 0;
	     decapId < CONFIG_YADECAP_DECAPS_SIZE;
	     decapId++)
	{
		decaps[decapId] = dataplane::globalBase::tDecap();
	}

	for (unsigned int interfaceId = 0;
	     interfaceId < CONFIG_YADECAP_INTERFACES_SIZE;
	     interfaceId++)
	{
		interfaces[interfaceId] = dataplane::globalBase::tInterface();
	}

	for (unsigned int nat64statefulId = 0;
	     nat64statefulId < YANET_CONFIG_NAT64STATEFULS_SIZE;
	     nat64statefulId++)
	{
		nat64statefuls[nat64statefulId] = dataplane::globalBase::nat64stateful_t();
	}

	for (unsigned int nat64statelessId = 0;
	     nat64statelessId < CONFIG_YADECAP_NAT64STATELESSES_SIZE;
	     nat64statelessId++)
	{
		nat64statelesses[nat64statelessId] = dataplane::globalBase::tNat64stateless();
	}

	for (unsigned int balancer_id = 0;
	     balancer_id < YANET_CONFIG_BALANCERS_SIZE;
	     balancer_id++)
	{
		balancers[balancer_id] = dataplane::globalBase::balancer_t();
	}

	tun64_enabled = 0;
	decap_enabled = 0;
	nat64stateful_enabled = 0;
	nat64stateless_enabled = 0;
	nat46clat_enabled = 0;
	balancer_enabled = 0;
	acl_egress_enabled = 0;
	sampler_enabled = 0;
	serial = 0;

	tun64mappingsTable.clear();

	for (unsigned int fw_state_sync_config_id = 0;
	     fw_state_sync_config_id < CONFIG_YADECAP_ACLS_SIZE;
	     fw_state_sync_config_id++)
	{
		fw_state_sync_configs[fw_state_sync_config_id] = fw_state_sync_config_t{};
	}

	// NOTE: we don't explicitly clear current fw states, as there might be responding packets.
	// Eventually the state-table will be flushed even if the a ruleset forbids
	// opening packets.

	return eResult::success;
}

static bool checkFlow(const common::globalBase::tFlow& flow)
{
	if (flow.type == common::globalBase::eFlowType::drop)
	{
	}
	else if (flow.type == common::globalBase::eFlowType::logicalPort_egress || flow.type == common::globalBase::eFlowType::acl_egress)
	{
		if (flow.data.logicalPortId >= CONFIG_YADECAP_LOGICALPORTS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::acl_ingress)
	{
		if (flow.data.aclId >= CONFIG_YADECAP_ACLS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::tun64_ipv4_checked ||
	         flow.type == common::globalBase::eFlowType::tun64_ipv6_checked)
	{
		if (flow.data.tun64Id >= CONFIG_YADECAP_TUN64_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::decap_checked)
	{
		if (flow.data.decapId >= CONFIG_YADECAP_DECAPS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::route ||
	         flow.type == common::globalBase::eFlowType::route_tunnel)
	{
		if (flow.data.routeId >= CONFIG_YADECAP_ROUTES_SIZE)
		{
			return false;
		}

		/// @todo: VRF
		if (flow.data.routeId != 0)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateful_lan)
	{
		if (flow.data.nat64stateful_id >= YANET_CONFIG_NAT64STATEFULS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateful_wan)
	{
		if (flow.data.nat64stateful_id >= YANET_CONFIG_NAT64STATEFULS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_ingress_checked)
	{
		if (flow.data.nat64stateless.id >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			return false;
		}

		if (flow.data.nat64stateless.translationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_ingress_icmp)
	{
		if (flow.data.nat64stateless.id >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			return false;
		}

		if (flow.data.nat64stateless.translationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_ingress_fragmentation)
	{
		if (flow.data.nat64stateless.id >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			return false;
		}

		if (flow.data.nat64stateless.translationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_checked)
	{
		if (flow.data.nat64stateless.id >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			return false;
		}

		if (flow.data.nat64stateless.translationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_icmp)
	{
		if (flow.data.nat64stateless.id >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			return false;
		}

		if (flow.data.nat64stateless.translationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_fragmentation)
	{
		if (flow.data.nat64stateless.id >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			return false;
		}

		if (flow.data.nat64stateless.translationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::nat64stateless_egress_farm)
	{
		if (flow.data.nat64stateless.id >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::balancer)
	{
		if (flow.data.balancer.id >= YANET_CONFIG_BALANCERS_SIZE)
		{
			return false;
		}

		if (flow.data.balancer.service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::acl_egress)
	{
		if (flow.data.aclId >= CONFIG_YADECAP_ACLS_SIZE)
		{
			return false;
		}
	}
	else if (flow.type == common::globalBase::eFlowType::controlPlane)
	{
	}
	else
	{
		return false;
	}

	return true;
}

eResult generation::updateLogicalPort(const common::idp::updateGlobalBase::updateLogicalPort::request& request)
{
	const auto& logicalPortId = std::get<0>(request);
	const auto& portId = std::get<1>(request);
	const auto& vlanId = std::get<2>(request);
	const auto& etherAddress = std::get<3>(request);
	const auto& promiscuousMode = std::get<4>(request);
	const auto& flow = std::get<5>(request);

	if (logicalPortId >= CONFIG_YADECAP_LOGICALPORTS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid logicalPortId: '%u'\n", logicalPortId);
		return eResult::invalidLogicalPortId;
	}
	if (!exist(dataPlane->ports, portId))
	{
		YADECAP_LOG_ERROR("invalid portId: '%u'\n", portId);
		return eResult::invalidPortId;
	}
	if (vlanId > 0x0FFF)
	{
		YADECAP_LOG_ERROR("invalid vlanId: '%u'\n", vlanId);
		return eResult::invalidVlanId;
	}
	if (flow.type != common::globalBase::eFlowType::acl_ingress &&
	    flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow type\n");
		return eResult::invalidFlow;
	}
	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& logicalPort = logicalPorts[logicalPortId];
	logicalPort.portId = portId;
	logicalPort.vlanId = rte_cpu_to_be_16(vlanId);
	memcpy(logicalPort.etherAddress.addr_bytes, etherAddress.data(), 6); ///< @todo: convert

	logicalPort.flags = 0;
	if (promiscuousMode)
	{
		logicalPort.flags |= YANET_LOGICALPORT_FLAG_PROMISCUOUSMODE;
	}

	logicalPort.flow = flow;

	return eResult::success;
}

eResult generation::tun64_update(const common::idp::updateGlobalBase::tun64_update::request& request)
{
	const auto& [tun64Id, dscpMarkType, dscp, srcRndFlag, ipv6AddressSource, flow] = request;

	if (tun64Id >= CONFIG_YADECAP_TUN64_SIZE)
	{
		YADECAP_LOG_ERROR("invalid tun64Id: '%u'\n", tun64Id);
		return eResult::invalidTun64Id;
	}

	if (flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::route_tunnel &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& tunnel = tun64tunnels[tun64Id];

	tunnel.srcRndEnabled = srcRndFlag ? 1 : 0;
	tunnel.ipv6AddressSource = ipv6_address_t::convert(ipv6AddressSource);
	tunnel.flow = flow;
	tunnel.isConfigured = 1;
	tun64_enabled = 1;

	if (dscpMarkType == common::eDscpMarkType::never)
	{
		tunnel.ipv4DSCPFlags = 0;
	}
	else if (dscpMarkType == common::eDscpMarkType::onlyDefault)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		tunnel.ipv4DSCPFlags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_MARK;
	}
	else if (dscpMarkType == common::eDscpMarkType::always)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		tunnel.ipv4DSCPFlags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_ALWAYS_MARK;
	}
	else
	{
		YADECAP_LOG_ERROR("invalid dscpMarkType\n");
		return eResult::invalidArguments;
	}

	return eResult::success;
}

eResult generation::tun64mappings_update(const common::idp::updateGlobalBase::tun64mappings_update::request& request)
{
	for (const auto& v : request)
	{
		const auto& [tun64Id, ipv4Address, ipv6Address, counter_id] = v;

		if (counter_id >= YANET_CONFIG_COUNTERS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid counter id %u\n", counter_id);
			return eResult::invalidCounterId;
		}

		if (!tun64mappingsTable.insert({tun64Id, ipv4Address}, {tun64Id, counter_id, ipv6_address_t::convert(ipv6Address)}))
		{
			YADECAP_LOG_ERROR("failed to insert mapping\n");
			return eResult::isFull;
		}
	}
	return eResult::success;
}

eResult generation::tsc_state_update(const common::idp::updateGlobalBase::tsc_state_update::request& request)
{
	tscs_active = request;
	return eResult::success;
}

eResult generation::tscs_base_value_update(const common::idp::updateGlobalBase::tscs_base_value_update::request& request)
{
	const auto& [offset, value] = request;
	*(uint32_t*)((uintptr_t)(&tsc_base_values) + offset) = value;

	return eResult::success;
}

eResult generation::updateDecap(const common::idp::updateGlobalBase::updateDecap::request& request)
{
	using common::eDscpMarkType;

	const auto& [decapId, dscpMarkType, dscp, flag_ipv6_enabled, flow] = request;

	if (decapId >= CONFIG_YADECAP_DECAPS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid decapId: '%u'\n", decapId);
		return eResult::invalidDecapId;
	}
	if (flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::route_tunnel &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}
	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& decap = decaps[decapId];

	if (dscpMarkType == eDscpMarkType::never)
	{
		decap.ipv4DSCPFlags = 0;
	}
	else if (dscpMarkType == eDscpMarkType::onlyDefault)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		decap.ipv4DSCPFlags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_MARK;
	}
	else if (dscpMarkType == eDscpMarkType::always)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		decap.ipv4DSCPFlags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_ALWAYS_MARK;
	}
	else
	{
		YADECAP_LOG_ERROR("invalid dscpMarkType\n");
		return eResult::invalidArguments;
	}

	decap.flag_ipv6_enabled = flag_ipv6_enabled;
	decap.flow = flow;

	decap_enabled = 1;

	return eResult::success;
}

eResult generation::updateDregress(const common::idp::updateGlobalBase::updateDregress::request& request)
{
	const auto& [dregressId, ipv4AddressSource, ipv6AddressSource, udpDestinationPort, onlyLongest, flow] = request;

	if (dregressId >= CONFIG_YADECAP_DREGRESS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid dregressId: '%u'\n", dregressId);
		return eResult::invalidId;
	}
	if (flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}
	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& dregress = dregresses[dregressId];

	dregress.ipv4AddressSource = ipv4_address_t::convert(ipv4AddressSource);
	dregress.ipv6AddressSource = ipv6_address_t::convert(ipv6AddressSource);
	dregress.udpDestinationPort = rte_cpu_to_be_16(udpDestinationPort);
	dregress.onlyLongest = onlyLongest;

	dregress.flow = flow;

	return eResult::success;
}

eResult generation::update_route(const common::idp::updateGlobalBase::update_route::request& request)
{
	const auto& [routeId, tunnel] = request;

	if (routeId >= CONFIG_YADECAP_ROUTES_SIZE)
	{
		YADECAP_LOG_ERROR("invalid routeId: '%u'\n", routeId);
		return eResult::invalidId;
	}

	auto& route = routes[routeId];

	if (tunnel)
	{
		const auto& [ipv4AddressSource, ipv6AddressSource, udpDestinationPort] = *tunnel;

		route.ipv4AddressSource = ipv4_address_t::convert(ipv4AddressSource);
		route.ipv6AddressSource = ipv6_address_t::convert(ipv6AddressSource);
		route.udpDestinationPort = rte_cpu_to_be_16(udpDestinationPort);
	}

	return eResult::success;
}

eResult generation::updateInterface(const common::idp::updateGlobalBase::updateInterface::request& request)
{
	const auto& [interfaceId, aclId, flow] = request;

	if (interfaceId >= CONFIG_YADECAP_INTERFACES_SIZE)
	{
		YADECAP_LOG_ERROR("invalid interfaceId: '%u'\n", interfaceId);
		return eResult::invalidInterfaceId;
	}
	if (flow.type != common::globalBase::eFlowType::logicalPort_egress &&
	    flow.type != common::globalBase::eFlowType::acl_egress &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}
	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& interface = interfaces[interfaceId];

	if (interface.aclId >= CONFIG_YADECAP_ACLS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid aclId\n");
		return eResult::invalidAclId;
	}

	interface.flow = flow;
	interface.aclId = aclId;

	if (aclId != YANET_ACL_ID_UNKNOWN)
	{
		acl_egress_enabled = 1;
	}

	return eResult::success;
}

eResult generation::nat64stateful_update(const common::idp::updateGlobalBase::nat64stateful_update::request& request)
{
	const auto& [nat64stateful_id, dscp_mark_type, dscp, counter_id, pool_start, pool_size, state_timeout, flow] = request;

	if (nat64stateful_id >= YANET_CONFIG_NAT64STATEFULS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid nat64stateful_id: '%u'\n", nat64stateful_id);
		return eResult::invalidId;
	}
	if (pool_start + pool_size > YANET_CONFIG_NAT64STATEFUL_POOL_SIZE)
	{
		YADECAP_LOG_ERROR("invalid nat64stateful pool: '%u, %u'\n",
		                  pool_start,
		                  pool_size);
		return eResult::invalidCount;
	}
	if (flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::route_tunnel &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}
	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& nat64stateful = nat64statefuls[nat64stateful_id];
	nat64stateful.pool_start = pool_start;
	nat64stateful.pool_size = pool_size;
	nat64stateful.counter_id = counter_id;
	nat64stateful.flow = flow;

	if (dscp_mark_type == common::eDscpMarkType::never)
	{
		nat64stateful.ipv4_dscp_flags = 0;
	}
	else if (dscp_mark_type == common::eDscpMarkType::onlyDefault)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		nat64stateful.ipv4_dscp_flags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_MARK;
	}
	else if (dscp_mark_type == common::eDscpMarkType::always)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		nat64stateful.ipv4_dscp_flags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_ALWAYS_MARK;
	}
	else
	{
		YADECAP_LOG_ERROR("invalid dscp_mark_type\n");
		return eResult::invalidArguments;
	}

	{
		const auto& [tcp_syn, tcp_ack, tcp_fin, udp, icmp, other] = state_timeout;

		nat64stateful.state_timeout.tcp_syn = tcp_syn;
		nat64stateful.state_timeout.tcp_ack = tcp_ack;
		nat64stateful.state_timeout.tcp_fin = tcp_fin;
		nat64stateful.state_timeout.udp = udp;
		nat64stateful.state_timeout.icmp = icmp;
		nat64stateful.state_timeout.other = other;
	}

	nat64stateful_enabled = 1;

	return eResult::success;
}

eResult generation::nat64stateful_pool_update(const common::idp::updateGlobalBase::nat64stateful_pool_update::request& request)
{
	uint32_t pool_size = 0;
	for (const auto& ipv4_prefix : request)
	{
		for (uint32_t i = 0;
		     i < (1u << (32 - ipv4_prefix.mask()));
		     i++)
		{
			if (pool_size + i >= YANET_CONFIG_NAT64STATEFUL_POOL_SIZE)
			{
				YADECAP_LOG_ERROR("invalid nat64stateful pool\n");
				return eResult::invalidFlow;
			}

			nat64stateful_pool[pool_size + i] = ipv4_address_t::convert(ipv4_prefix.address() + i);
		}

		pool_size += (1u << (32 - ipv4_prefix.mask()));
	}

	return eResult::success;
}

eResult generation::updateNat64stateless(const common::idp::updateGlobalBase::updateNat64stateless::request& request)
{
	using common::eDscpMarkType;

	const auto& [nat64statelessId, dscpMarkType, dscp, firewall, flow, defrag_farm_prefix, defrag_source_prefix, farm] = request;

	if (nat64statelessId >= CONFIG_YADECAP_NAT64STATELESSES_SIZE)
	{
		YADECAP_LOG_ERROR("invalid nat64statelessId: '%u'\n", nat64statelessId);
		return eResult::invalidNat64statelessId;
	}
	if (flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::route_tunnel &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}
	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& nat64stateless = nat64statelesses[nat64statelessId];

	if (dscpMarkType == eDscpMarkType::never)
	{
		nat64stateless.ipv4DSCPFlags = 0;
	}
	else if (dscpMarkType == eDscpMarkType::onlyDefault)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		nat64stateless.ipv4DSCPFlags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_MARK;
	}
	else if (dscpMarkType == eDscpMarkType::always)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		nat64stateless.ipv4DSCPFlags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_ALWAYS_MARK;
	}
	else
	{
		YADECAP_LOG_ERROR("invalid dscpMarkType\n");
		return eResult::invalidArguments;
	}

	nat64stateless.firewall = firewall;
	nat64stateless.flow = flow;
	nat64stateless.farm = farm;
	if (defrag_farm_prefix)
	{
		nat64stateless.defrag_farm_prefix = ipv6_address_t::convert(defrag_farm_prefix.value());
		nat64stateless.defrag_source_prefix = ipv6_address_t::convert(defrag_source_prefix.value());
	}
	else
	{
		nat64stateless.defrag_farm_prefix.reset();
		nat64stateless.defrag_source_prefix.reset();
	}

	nat64stateless_enabled = 1;

	return eResult::success;
}

eResult generation::updateNat64statelessTranslation(const common::idp::updateGlobalBase::updateNat64statelessTranslation::request& request)
{
	const auto& [nat64statelessTranslationId,
	             ipv6Address,
	             ipv6DestinationAddress,
	             ipv4Address,
	             range] = request;

	if (nat64statelessTranslationId >= CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid nat64statelessTranslationId: '%u'\n", nat64statelessTranslationId);
		return eResult::invalidNat64statelessTranslationId;
	}

	auto& nat64statelessTranslation = nat64statelessTranslations[nat64statelessTranslationId];

	nat64statelessTranslation.ipv6Address = ipv6_address_t::convert(ipv6Address);
	nat64statelessTranslation.ipv6DestinationAddress = ipv6_address_t::convert(ipv6DestinationAddress);
	nat64statelessTranslation.ipv4Address = ipv4_address_t::convert(ipv4Address);
	nat64statelessTranslation.flags = 0;
	nat64statelessTranslation.diffPort = 0;

	if (range)
	{
		const auto& [ingressPort, egressPort] = *range;

		nat64statelessTranslation.flags |= YANET_TRANSLATION_FLAG_RANGE;
		nat64statelessTranslation.diffPort = egressPort - ingressPort;
	}

	return eResult::success;
}

eResult generation::nat46clat_update(const common::idp::updateGlobalBase::nat46clat_update::request& request)
{
	const auto& [nat46clat_id, ipv6_source, ipv6_destination, dscp_mark_type, dscp, counter_id, flow] = request;

	if (nat46clat_id >= YANET_CONFIG_NAT46CLATS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid nat46clat_id: '%u'\n", nat46clat_id);
		return eResult::invalidId;
	}

	if (flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::route_tunnel &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& nat46clat = nat46clats[nat46clat_id];
	nat46clat.ipv6_source = ipv6_address_t::convert(ipv6_source);
	nat46clat.ipv6_destination = ipv6_address_t::convert(ipv6_destination);
	nat46clat.counter_id = counter_id;
	nat46clat.flow = flow;

	if (dscp_mark_type == common::eDscpMarkType::never)
	{
		nat46clat.ipv4_dscp_flags = 0;
	}
	else if (dscp_mark_type == common::eDscpMarkType::onlyDefault)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		nat46clat.ipv4_dscp_flags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_MARK;
	}
	else if (dscp_mark_type == common::eDscpMarkType::always)
	{
		if (dscp > 0x3F)
		{
			YADECAP_LOG_ERROR("invalid dscp\n");
			return eResult::invalidArguments;
		}

		nat46clat.ipv4_dscp_flags = (dscp << 2) | YADECAP_GB_DSCP_FLAG_ALWAYS_MARK;
	}
	else
	{
		YADECAP_LOG_ERROR("invalid dscp_mark_type\n");
		return eResult::invalidArguments;
	}

	nat46clat_enabled = 1;

	return eResult::success;
}

eResult generation::update_balancer(const common::idp::updateGlobalBase::update_balancer::request& request)
{
	const auto& [balancer_id, source_ipv6, source_ipv4, flow] = request;

	if (balancer_id >= YANET_CONFIG_BALANCERS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid balancer_id: '%u'\n", balancer_id);
		return eResult::invalidId;
	}
	if (flow.type != common::globalBase::eFlowType::route &&
	    flow.type != common::globalBase::eFlowType::controlPlane &&
	    flow.type != common::globalBase::eFlowType::drop)
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}
	if (!checkFlow(flow))
	{
		YADECAP_LOG_ERROR("invalid flow\n");
		return eResult::invalidFlow;
	}

	auto& balancer = balancers[balancer_id];

	balancer.source_ipv6 = ipv6_address_t::convert(source_ipv6);
	balancer.source_ipv4 = ipv4_address_t::convert(source_ipv4);

	balancer.flow = flow;

	balancer_enabled = 1;

	return eResult::success;
}

eResult generation::update_balancer_services(const common::idp::updateGlobalBase::update_balancer_services::request& request)
{
	DEBUG_LATCH_WAIT(common::idp::debug_latch_update::id::global_base_update_balancer);
	std::lock_guard<std::mutex> guard(dataPlane->controlPlane->balancer_mutex);

	const auto& services = std::get<0>(request);
	if (services.size() > YANET_CONFIG_BALANCER_SERVICES_SIZE)
	{
		YADECAP_LOG_ERROR("invalid service size: '%lu'\n", services.size());
		return eResult::invalidId;
	}
	balancer_services_count = 0;

	for (const auto& [balancer_service_id,
	                  flags,
	                  counter_id,
	                  scheduler,
	                  forwarding_method,
	                  default_wlc_power,
	                  real_start,
	                  real_size,
	                  ipv4_outer_source_network,
	                  ipv6_outer_source_network] : services)
	{
		if (balancer_service_id >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
		{
			YADECAP_LOG_ERROR("invalid balancer_service_id: '%u'\n", balancer_service_id);
			return eResult::invalidId;
		}

		if (counter_id + (tCounterId)::balancer::service_counter::size > YANET_CONFIG_COUNTERS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid counter_id: '%u'\n", counter_id);
			return eResult::invalidId;
		}

		if (real_start + real_size > YANET_CONFIG_BALANCER_REALS_SIZE)
		{
			YADECAP_LOG_WARNING("invalid real. real_start: '%u', real_size: '%u'\n",
			                    real_start,
			                    real_size);
			return eResult::invalidCount;
		}

		uint8_t outer_source_network_flag = 0;
		ipv4_prefix_t ipv4_prefix;
		if (ipv4_outer_source_network)
		{
			outer_source_network_flag |= IPv4_OUTER_SOURCE_NETWORK_FLAG;
			ipv4_prefix.address = ipv4_prefix.address.convert(ipv4_outer_source_network.value().address());
			ipv4_prefix.mask = ipv4_outer_source_network.value().mask();
		}

		ipv6_prefix_t ipv6_prefix;
		if (ipv6_outer_source_network)
		{
			outer_source_network_flag |= IPv6_OUTER_SOURCE_NETWORK_FLAG;
			ipv6_prefix.address = ipv6_prefix.address.convert(ipv6_outer_source_network.value().address());
			ipv6_prefix.mask = ipv6_outer_source_network.value().mask();
		}

		balancer_active_services[balancer_services_count++] = balancer_service_id;
		auto& balancer_service = balancer_services[balancer_service_id];

		balancer_service.flags = flags;
		balancer_service.counter_id = counter_id;
		balancer_service.real_start = real_start;
		balancer_service.real_size = real_size;
		balancer_service.scheduler = scheduler;
		balancer_service.wlc_power = default_wlc_power;
		balancer_service.forwarding_method = forwarding_method;
		balancer_service.outer_source_network_flag = outer_source_network_flag;
		balancer_service.ipv4_outer_source_network = ipv4_prefix;
		balancer_service.ipv6_outer_source_network = ipv6_prefix;
	}

	const auto& reals = std::get<1>(request);
	if (reals.size() > YANET_CONFIG_BALANCER_REALS_SIZE)
	{
		YADECAP_LOG_WARNING("invalid real. real_sise: '%lu'\n",
		                    reals.size());
		return eResult::invalidCount;
	}

	for (const auto& [real_id, destination, counter_id] : reals)
	{
		if (real_id >= YANET_CONFIG_BALANCER_REALS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid real_id: '%u'\n", real_id);
			return eResult::invalidId;
		}

		auto& real_unordered = balancer_reals[real_id];

		if (counter_id + (tCounterId)::balancer::real_counter::size > YANET_CONFIG_COUNTERS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid counter_id: '%u'\n", counter_id);
			return eResult::invalidId;
		}

		auto addr = ipv6_address_t::convert(destination);
		if (real_unordered.counter_id != counter_id || real_unordered.destination != addr)
		{
			for (tCounterId i = 0; i < (tCounterId)::balancer::real_counter::size; ++i)
			{
				uint64_t sum_worker = 0, sum_gc = 0;
				for (const auto& [core_id, worker] : dataPlane->workers)
				{
					(void)core_id;
					sum_worker += worker->counters[counter_id + i];
				}
				for (const auto& [core_id, worker_gc] : dataPlane->worker_gcs)
				{
					(void)core_id;
					sum_gc += worker_gc->counters[counter_id + i];
				}
				for (const auto& item : dataPlane->globalBaseAtomics)
				{
					item.second->counter_shifts[counter_id + i] = sum_worker;
					item.second->gc_counter_shifts[counter_id + i] = sum_gc;
				}
			}
		}
		real_unordered.destination = addr;
		real_unordered.counter_id = counter_id;
		real_unordered.flags = 0;
		if (destination.is_ipv6())
		{
			real_unordered.flags |= YANET_BALANCER_FLAG_DST_IPV6;
		}
	}

	const auto& binding = std::get<2>(request);
	if (binding.size() >= YANET_CONFIG_BALANCER_REALS_SIZE)
	{
		YADECAP_LOG_WARNING("invalid real binding. real_sise: '%lu'\n",
		                    reals.size());
		return eResult::invalidCount;
	}

	for (const auto& real_id : binding)
	{
		if (real_id >= YANET_CONFIG_BALANCER_REALS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid real_id: '%u'\n", real_id);
			return eResult::invalidId;
		}
	}

	std::copy(binding.begin(), binding.end(), balancer_service_reals);

	evaluate_service_ring();

	return eResult::success;
}

eResult generation::update_balancer_unordered_real(const common::idp::updateGlobalBaseBalancer::update_balancer_unordered_real::request& request)
{
	for (const auto& [real_id, enabled, weight] : request)
	{
		if (real_id >= YANET_CONFIG_BALANCER_REALS_SIZE)
		{
			YADECAP_LOG_ERROR("invalid real_id: '%u'\n", real_id);
			return eResult::invalidId;
		}

		auto& real_state = balancer_real_states[real_id];

		balancer_real_state_t new_state;
		new_state.flags = enabled ? YANET_BALANCER_FLAG_ENABLED : 0;
		new_state.weight = enabled ? weight : 0;
		real_state = new_state;
	}

	evaluate_service_ring();

	return eResult::success;
}

double wlc_ratio(uint32_t weight, uint32_t connections, uint32_t weight_sum, uint32_t connection_sum, uint32_t power)
{
	if (weight == 0 || weight_sum == 0 || connection_sum < weight_sum)
	{
		return 1;
	}
	auto a = power * (1 - 1.0 * connections * weight_sum / connection_sum / weight);
	return std::max(1.0, a);
}

inline uint64_t generation::count_real_connections(uint32_t counter_id)
{
	uint64_t sessions_created = 0;
	uint64_t sessions_destroyed = 0;
	for (const auto& [core_id, worker] : dataPlane->workers)
	{
		(void)core_id;
		sessions_created += worker->counters[counter_id + (tCounterId)::balancer::real_counter::sessions_created];
		sessions_destroyed += worker->counters[counter_id + (tCounterId)::balancer::real_counter::sessions_destroyed];
	}
	sessions_created -= dataPlane->globalBaseAtomics[socketId]->counter_shifts[counter_id + (tCounterId)::balancer::real_counter::sessions_created];
	sessions_destroyed -= dataPlane->globalBaseAtomics[socketId]->counter_shifts[counter_id + (tCounterId)::balancer::real_counter::sessions_destroyed];

	uint64_t sessions_created_gc = 0;
	uint64_t sessions_destroyed_gc = 0;
	for (const auto& [node_id, worker_gc] : dataPlane->worker_gcs)
	{
		(void)node_id;
		sessions_created_gc += worker_gc->counters[counter_id + (tCounterId)::balancer::gc_real_counter::sessions_created];
		sessions_destroyed_gc += worker_gc->counters[counter_id + (tCounterId)::balancer::gc_real_counter::sessions_destroyed];
	}
	sessions_created_gc -= dataPlane->globalBaseAtomics[socketId]->gc_counter_shifts[counter_id + (tCounterId)::balancer::gc_real_counter::sessions_created];
	sessions_destroyed_gc -= dataPlane->globalBaseAtomics[socketId]->gc_counter_shifts[counter_id + (tCounterId)::balancer::gc_real_counter::sessions_destroyed];
	return (sessions_created - sessions_destroyed + sessions_created_gc - sessions_destroyed_gc) / dataPlane->numaNodesInUse;
}

void generation::evaluate_service_ring()
{
	balancer_service_ring_t* ring = &balancer_service_ring;
	uint32_t weight_pos = 0;
	for (uint32_t service_idx = 0; service_idx < balancer_services_count; ++service_idx)
	{
		balancer_service_t* service = balancer_services + balancer_active_services[service_idx];
		uint64_t connection_sum = 0;
		uint32_t weight_sum = 0;
		if (service->scheduler == ::balancer::scheduler::wlc)
		{
			for (uint32_t real_idx = service->real_start;
			     real_idx < service->real_start + service->real_size;
			     ++real_idx)
			{
				uint32_t real_id = balancer_service_reals[real_idx];
				balancer_real_state_t* state = balancer_real_states + real_id;
				// don`t count connections for disabled reals - it can make other reals "feel" underloaded
				if (state->weight == 0)
				{
					continue;
				}
				weight_sum += state->weight;

				const balancer_real_t& real = balancer_reals[real_id];
				connection_sum += count_real_connections(real.counter_id);
			}
		}

		balancer_service_range_t* range = ring->ranges + balancer_active_services[service_idx];

		range->start = weight_pos;
		for (uint32_t real_idx = service->real_start;
		     real_idx < service->real_start + service->real_size;
		     ++real_idx)
		{
			uint32_t real_id = balancer_service_reals[real_idx];
			const balancer_real_t& real = balancer_reals[real_id];
			balancer_real_state_t* state = balancer_real_states + real_id;

			if (state->weight == 0)
			{
				continue;
			}

			auto weight = state->weight;

			if (service->scheduler == ::balancer::scheduler::wlc)
			{
				uint64_t real_connections = count_real_connections(real.counter_id);

				weight = (int)(weight * wlc_ratio(state->weight, real_connections, weight_sum, connection_sum, service->wlc_power));
				// todo check weight change
			}

			// clamp weight to a maximum possible value
			if (weight > YANET_CONFIG_BALANCER_REAL_WEIGHT_MAX)
			{
				// TODO: think about accounting the clamping
				weight = YANET_CONFIG_BALANCER_REAL_WEIGHT_MAX;
			}

			while (weight-- > 0)
			{
				ring->reals[weight_pos++] = real_id;
			}
		}

		YADECAP_MEMORY_BARRIER_COMPILE;

		range->size = weight_pos - range->start;
		weight_pos = range->start + service->real_size * YANET_CONFIG_BALANCER_REAL_WEIGHT_MAX;
	}
}

eResult generation::route_lpm_update(const common::idp::updateGlobalBase::route_lpm_update::request& request)
{
	eResult result = eResult::success;

	for (const auto& action : request)
	{
		if (const auto update = std::get_if<common::idp::lpm::insert>(&action))
		{
			for (const auto& [prefix, value_id] : *update)
			{
				if (prefix.is_ipv4())
				{
					result = updater.route_lpm4->insert(prefix.get_ipv4().address(),
					                                    prefix.get_ipv4().mask(),
					                                    value_id);
				}
				else
				{
					result = updater.route_lpm6->insert(prefix.get_ipv6().address(),
					                                    prefix.get_ipv6().mask(),
					                                    value_id);
				}

				if (result != eResult::success)
				{
					return result;
				}
			}
		}
		else if (const auto remove = std::get_if<common::idp::lpm::remove>(&action))
		{
			for (const auto& prefix : *remove)
			{
				if (prefix.is_ipv4())
				{
					result = updater.route_lpm4->remove(prefix.get_ipv4().address(),
					                                    prefix.get_ipv4().mask());
				}
				else
				{
					result = updater.route_lpm6->remove(prefix.get_ipv6().address(),
					                                    prefix.get_ipv6().mask());
				}

				if (result != eResult::success)
				{
					return result;
				}
			}
		}
		else
		{
			YADECAP_LOG_DEBUG("route lpm clear\n");

			updater.route_lpm4->clear();
			updater.route_lpm6->clear();

			return eResult::success;
		}
	}

	route_lpm4 = updater.route_lpm4->pointer();
	route_lpm6 = updater.route_lpm6->pointer();

	return result;
}

eResult generation::route_value_update(const common::idp::updateGlobalBase::route_value_update::request& request)
{
	eResult result = eResult::success;

	const auto& [request_route_value_id, request_socket_id, request_type, request_interface] = request;

	if (socketId != request_socket_id)
	{
		return result;
	}

	if (request_route_value_id >= YANET_CONFIG_ROUTE_VALUES_SIZE)
	{
		YADECAP_LOG_ERROR("invalid value id: '%u'\n", request_route_value_id);
		return eResult::invalidValueId;
	}

	auto& route_value = route_values[request_route_value_id];
	route_value.type = common::globalBase::eNexthopType::drop;

	if (request_type == common::globalBase::eNexthopType::drop)
	{
		route_value.type = request_type;
	}
	else if (request_type == common::globalBase::eNexthopType::interface)
	{
		if (request_interface.size() == 0 ||
		    request_interface.size() > CONFIG_YADECAP_GB_ECMP_SIZE)
		{
			YADECAP_LOG_WARNING("invalid ecmp count: '%lu'\n", request_interface.size());
			return eResult::invalidCount;
		}

		for (unsigned int ecmp_i = 0;
		     ecmp_i < request_interface.size();
		     ecmp_i++)
		{
			const auto& [interface_id, labels, neighbor_address, nexthop_flags] = request_interface[ecmp_i];

			if (interface_id >= CONFIG_YADECAP_INTERFACES_SIZE)
			{
				YADECAP_LOG_ERROR("invalid interfaceId: '%u'\n", interface_id);
				return eResult::invalidInterfaceId;
			}

			route_value.interface.nexthops[ecmp_i].interfaceId = interface_id;
			route_value.interface.nexthops[ecmp_i].flags = nexthop_flags;
			route_value.interface.nexthops[ecmp_i].neighbor_address = ipv6_address_t::convert(neighbor_address);
			route_value.interface.nexthops[ecmp_i].is_ipv6 = neighbor_address.is_ipv6();

			if (labels.size() == 0)
			{
				route_value.interface.nexthops[ecmp_i].labelExpTransport = 0;
				route_value.interface.nexthops[ecmp_i].labelExpService = 0;
			}
			else
			{
				uint8_t expFirst = 0; ///< @todo: tag:ROUTE_EXP
				uint8_t expSecond = 0; ///< @todo: tag:ROUTE_EXP

				route_value.interface.nexthops[ecmp_i].labelExpTransport = ((labels[0] & 0xFFFFF) << 12) | ((expFirst & 0x7) << 9) | 0xFF;

				if (labels.size() == 1)
				{
					route_value.interface.nexthops[ecmp_i].labelExpTransport |= (1 << 8); ///< bottom of stack
					route_value.interface.nexthops[ecmp_i].labelExpService = 0;
				}
				else
				{
					route_value.interface.nexthops[ecmp_i].labelExpService = ((labels[1] & 0xFFFFF) << 12) | ((expSecond & 0x7) << 9) | 0xFF | 0x100;
				}
			}

			route_value.interface.nexthops[ecmp_i].labelExpTransport = rte_cpu_to_be_32(route_value.interface.nexthops[ecmp_i].labelExpTransport);
			route_value.interface.nexthops[ecmp_i].labelExpService = rte_cpu_to_be_32(route_value.interface.nexthops[ecmp_i].labelExpService);
		}

		route_value.interface.ecmpCount = request_interface.size();

		route_value.type = request_type;
	}
	else if (request_type == common::globalBase::eNexthopType::controlPlane)
	{
		route_value.type = request_type;
	}
	else if (request_type == common::globalBase::eNexthopType::repeat)
	{
		route_value.type = request_type;
	}
	else
	{
		YADECAP_LOG_ERROR("invalid nexthop type\n");
		return eResult::invalidType;
	}

	return result;
}

eResult generation::route_tunnel_lpm_update(const common::idp::updateGlobalBase::route_tunnel_lpm_update::request& request)
{
	eResult result = eResult::success;

	for (const auto& action : request)
	{
		if (const auto update = std::get_if<common::idp::lpm::insert>(&action))
		{
			for (const auto& [prefix, value_id] : *update)
			{
				if (prefix.is_ipv4())
				{
					result = updater.route_tunnel_lpm4->insert(prefix.get_ipv4().address(),
					                                           prefix.get_ipv4().mask(),
					                                           value_id);
				}
				else
				{
					result = updater.route_tunnel_lpm6->insert(prefix.get_ipv6().address(),
					                                           prefix.get_ipv6().mask(),
					                                           value_id);
				}

				if (result != eResult::success)
				{
					return result;
				}
			}
		}
		else if (const auto remove = std::get_if<common::idp::lpm::remove>(&action))
		{
			for (const auto& prefix : *remove)
			{
				if (prefix.is_ipv4())
				{
					result = updater.route_tunnel_lpm4->remove(prefix.get_ipv4().address(),
					                                           prefix.get_ipv4().mask());
				}
				else
				{
					result = updater.route_tunnel_lpm6->remove(prefix.get_ipv6().address(),
					                                           prefix.get_ipv6().mask());
				}

				if (result != eResult::success)
				{
					return result;
				}
			}
		}
		else
		{
			YADECAP_LOG_DEBUG("route_tunnel lpm clear\n");

			updater.route_tunnel_lpm4->clear();
			updater.route_tunnel_lpm6->clear();

			return eResult::success;
		}
	}

	route_tunnel_lpm4 = updater.route_tunnel_lpm4->pointer();
	route_tunnel_lpm6 = updater.route_tunnel_lpm6->pointer();

	return result;
}

eResult generation::route_tunnel_weight_update(const common::idp::updateGlobalBase::route_tunnel_weight_update::request& request)
{
	if (request.size() > YANET_CONFIG_ROUTE_TUNNEL_WEIGHTS_SIZE)
	{
		YADECAP_LOG_ERROR("invalid size: '%lu'\n", request.size());
		return eResult::invalidCount;
	}

	std::copy(request.begin(), request.end(), route_tunnel_weights);

	return eResult::success;
}

eResult generation::route_tunnel_value_update(const common::idp::updateGlobalBase::route_tunnel_value_update::request& request)
{
	eResult result = eResult::success;

	const auto& [request_route_tunnel_value_id, request_socket_id, request_type, request_interface] = request;

	if (socketId != request_socket_id)
	{
		return result;
	}

	if (request_route_tunnel_value_id >= YANET_CONFIG_ROUTE_TUNNEL_VALUES_SIZE)
	{
		YADECAP_LOG_ERROR("invalid value id: '%u'\n", request_route_tunnel_value_id);
		return eResult::invalidValueId;
	}

	auto& route_tunnel_value = route_tunnel_values[request_route_tunnel_value_id];
	route_tunnel_value.type = common::globalBase::eNexthopType::drop;

	if (request_type == common::globalBase::eNexthopType::drop)
	{
		route_tunnel_value.type = request_type;
	}
	else if (request_type == common::globalBase::eNexthopType::interface)
	{
		const auto& [weight_start, weight_size, nexthops] = request_interface;

		if (weight_size == 0 ||
		    weight_start + weight_size > YANET_CONFIG_ROUTE_TUNNEL_WEIGHTS_SIZE)
		{
			YADECAP_LOG_WARNING("invalid weight. weight_start: '%u', weight_size: '%u'\n",
			                    weight_start,
			                    weight_size);
			return eResult::invalidCount;
		}

		if (nexthops.size() == 0 ||
		    nexthops.size() > YANET_CONFIG_ROUTE_TUNNEL_ECMP_SIZE)
		{
			YADECAP_LOG_WARNING("invalid ecmp count: '%lu'\n", nexthops.size());
			return eResult::invalidCount;
		}

		for (unsigned int ecmp_i = 0;
		     ecmp_i < nexthops.size();
		     ecmp_i++)
		{
			const auto& [interface_id, counter_id, label, nexthop_address, neighbor_address, nexthop_flags] = nexthops[ecmp_i];

			if (interface_id >= CONFIG_YADECAP_INTERFACES_SIZE)
			{
				YADECAP_LOG_ERROR("invalid interfaceId: '%u'\n", interface_id);
				return eResult::invalidInterfaceId;
			}

			route_tunnel_value.interface.nexthops[ecmp_i].interface_id = interface_id;
			route_tunnel_value.interface.nexthops[ecmp_i].flags = nexthop_flags;
			route_tunnel_value.interface.nexthops[ecmp_i].counter_id = counter_id;
			route_tunnel_value.interface.nexthops[ecmp_i].label = label;
			route_tunnel_value.interface.nexthops[ecmp_i].nexthop_address = ipv6_address_t::convert(nexthop_address);
			route_tunnel_value.interface.nexthops[ecmp_i].neighbor_address = ipv6_address_t::convert(neighbor_address);
			route_tunnel_value.interface.nexthops[ecmp_i].is_ipv6 = nexthop_address.is_ipv6();
		}

		route_tunnel_value.interface.weight_start = weight_start;
		route_tunnel_value.interface.weight_size = weight_size;

		route_tunnel_value.type = request_type;
	}
	else if (request_type == common::globalBase::eNexthopType::controlPlane)
	{
		route_tunnel_value.type = request_type;
	}
	else if (request_type == common::globalBase::eNexthopType::repeat)
	{
		route_tunnel_value.type = request_type;
	}
	else
	{
		YADECAP_LOG_ERROR("invalid nexthop type\n");
		return eResult::invalidType;
	}

	return result;
}

eResult generation::update_early_decap_flags(const common::idp::updateGlobalBase::update_early_decap_flags::request& request)
{
	eResult result = eResult::success;

	early_decap_enabled = request;

	return result;
}

eResult generation::acl_network_ipv4_source(const common::idp::updateGlobalBase::acl_network_ipv4_source::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.network_ipv4_source->update(request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.network.ipv4.source.update(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.network.ipv4.source = updater.acl.network_ipv4_source->pointer;

	return result;
}

eResult generation::acl_network_ipv4_destination(const common::idp::updateGlobalBase::acl_network_ipv4_destination::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.network_ipv4_destination->update(request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.network.ipv4.destination.update(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.network.ipv4.destination = updater.acl.network_ipv4_destination->pointer;

	return result;
}

eResult generation::acl_network_ipv6_source(const common::idp::updateGlobalBase::acl_network_ipv6_source::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.network_ipv6_source->update(request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.network.ipv6.source.update(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.network.ipv6.source = updater.acl.network_ipv6_source->pointer;

	return result;
}

eResult generation::acl_network_ipv6_destination_ht(const common::idp::updateGlobalBase::acl_network_ipv6_destination_ht::request& request)
{
	std::vector<std::tuple<ipv6_address_t, tAclGroupId>> request_convert;
	for (const auto& [address, group_id] : request)
	{
		request_convert.emplace_back(ipv6_address_t::convert(address), group_id);
	}

	/// ignore error
	updater.acl.network_ipv6_destination_ht->update(request_convert, false);
	acl.network.ipv6.destination_ht = updater.acl.network_ipv6_destination_ht->pointer;

	return eResult::success;
}

eResult generation::acl_network_ipv6_destination(const common::idp::updateGlobalBase::acl_network_ipv6_destination::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.network_ipv6_destination->update(request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.network.ipv6.destination.update(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.network.ipv6.destination = updater.acl.network_ipv6_destination->pointer;

	return result;
}

eResult generation::acl_network_table(const common::idp::updateGlobalBase::acl_network_table::request& request)
{
	eResult result = eResult::success;

	const auto& [width, values] = request;

	result = updater.acl.network_table->update(width, values);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.network_table.update(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.network_table = updater.acl.network_table->pointer;

	return result;
}

eResult generation::acl_network_flags(const common::idp::updateGlobalBase::acl_network_flags::request& request)
{
	eResult result = eResult::success;

	flat<uint8_t>::updater updater_network_flags; ///< @todo
	result = acl.network_flags.update(updater_network_flags, request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.network_flags.update(): %s\n", result_to_c_str(result));
		return result;
	}

	return result;
}

eResult generation::acl_transport_layers(const common::idp::updateGlobalBase::acl_transport_layers::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.transport_layers->create(request.size());
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.transport_layers.create(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.transport_layers = updater.acl.transport_layers->pointer;

	for (unsigned int layer_id = 0;
	     layer_id < request.size();
	     layer_id++)
	{
		auto& transport_layer = acl.transport_layers[layer_id];

		const auto& [protocol,
		             tcp_source,
		             tcp_destination,
		             tcp_flags,
		             udp_source,
		             udp_destination,
		             icmp_type_code,
		             icmp_identifier] = request[layer_id];

		flat<uint8_t>::updater updater_protocol; ///< @todo
		result = transport_layer.protocol.update(updater_protocol, protocol);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.protocol.update(): %s\n", result_to_c_str(result));
			return result;
		}

		flat<uint16_t>::updater updater_tcp_source; ///< @todo
		result = transport_layer.tcp.source.update(updater_tcp_source, tcp_source);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.tcp.source.update(): %s\n", result_to_c_str(result));
			return result;
		}

		flat<uint16_t>::updater updater_tcp_destination; ///< @todo
		result = transport_layer.tcp.destination.update(updater_tcp_destination, tcp_destination);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.tcp.destination.update(): %s\n", result_to_c_str(result));
			return result;
		}

		flat<uint8_t>::updater updater_tcp_flags; ///< @todo
		result = transport_layer.tcp.flags.update(updater_tcp_flags, tcp_flags);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.tcp.flags.update(): %s\n", result_to_c_str(result));
			return result;
		}

		flat<uint16_t>::updater updater_udp_source; ///< @todo
		result = transport_layer.udp.source.update(updater_udp_source, udp_source);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.udp.source.update(): %s\n", result_to_c_str(result));
			return result;
		}

		flat<uint16_t>::updater updater_udp_destination; ///< @todo
		result = transport_layer.udp.destination.update(updater_udp_destination, udp_destination);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.udp.destination.update(): %s\n", result_to_c_str(result));
			return result;
		}

		flat<uint16_t>::updater updater_icmp_type_code; ///< @todo
		result = transport_layer.icmp.type_code.update(updater_icmp_type_code, icmp_type_code);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.icmp.type_code.update(): %s\n", result_to_c_str(result));
			return result;
		}

		flat<uint16_t>::updater updater_icmp_identifier; ///< @todo
		result = transport_layer.icmp.identifier.update(updater_icmp_identifier, icmp_identifier);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("acl.transport_layer.icmp.identifier.update(): %s\n", result_to_c_str(result));
			return result;
		}
	}

	acl.transport_layers_mask = upper_power_of_two(request.size()) - 1;

	return result;
}

eResult generation::acl_transport_table(const common::idp::updateGlobalBase::acl_transport_table::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.transport_table->update(request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.transport_table.update(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.transport_table = updater.acl.transport_table->pointer;

	return result;
}

eResult generation::acl_total_table(const common::idp::updateGlobalBase::acl_total_table::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.total_table->update(request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.total_table.update(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.total_table = updater.acl.total_table->pointer;

	return result;
}

eResult generation::acl_values(const common::idp::updateGlobalBase::acl_values::request& request)
{
	eResult result = eResult::success;

	result = updater.acl.values->create(request.size());
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("acl.values.create(): %s\n", result_to_c_str(result));
		return result;
	}

	acl.values = updater.acl.values->pointer;

	std::copy(request.begin(), request.end(), acl.values);

	return eResult::success;
}

eResult generation::dump_tags_ids(const common::idp::updateGlobalBase::dump_tags_ids::request& request)
{
	memset(dump_id_to_tag, -1, sizeof(dump_id_to_tag));

	for (size_t i = 0; i < request.size(); i++)
	{
		auto it = dataPlane->tag_to_id.find(request[i]);
		if (it != dataPlane->tag_to_id.end())
		{
			dump_id_to_tag[i + 1] = it->second;
		}
	}

	return eResult::success;
}

eResult generation::dregress_prefix_update(const common::idp::updateGlobalBase::dregress_prefix_update::request& request)
{
	eResult result = eResult::success;

	for (const auto& [prefix, value_id] : request)
	{
		std::lock_guard<std::mutex> guard(dataPlane->controlPlane->dregress.prefixes_mutex);
		dataPlane->controlPlane->dregress.prefixes.insert(prefix, value_id);
	}

	return result;
}

eResult generation::dregress_prefix_remove(const common::idp::updateGlobalBase::dregress_prefix_remove::request& request)
{
	eResult result = eResult::success;

	for (const auto& prefix : request)
	{
		std::lock_guard<std::mutex> guard(dataPlane->controlPlane->dregress.prefixes_mutex);
		dataPlane->controlPlane->dregress.prefixes.remove(prefix);
	}

	return result;
}

eResult generation::dregress_prefix_clear()
{
	eResult result = eResult::success;

	std::lock_guard<std::mutex> guard(dataPlane->controlPlane->dregress.prefixes_mutex);
	dataPlane->controlPlane->dregress.prefixes.clear();

	return result;
}

eResult generation::dregress_local_prefix_update(const common::idp::updateGlobalBase::dregress_local_prefix_update::request& request)
{
	eResult result = eResult::success;

	std::lock_guard<std::mutex> guard(dataPlane->controlPlane->dregress.prefixes_mutex);

	dataPlane->controlPlane->dregress.local_prefixes_v4.clear();
	dataPlane->controlPlane->dregress.local_prefixes_v6.clear();

	for (const auto& prefix : request)
	{
		if (prefix.is_ipv4())
		{
			dataPlane->controlPlane->dregress.local_prefixes_v4.emplace(prefix.get_ipv4());
		}
		else
		{
			dataPlane->controlPlane->dregress.local_prefixes_v6.emplace(prefix.get_ipv6());
		}
	}

	return result;
}

eResult generation::dregress_value_update(const common::idp::updateGlobalBase::dregress_value_update::request& request)
{
	eResult result = eResult::success;

	std::lock_guard<std::mutex> guard(dataPlane->controlPlane->dregress.prefixes_mutex);

	for (const auto& [value_id, value] : request)
	{
		/// @todo: check value_id

		dataPlane->controlPlane->dregress.values[value_id] = value;
	}

	return result;
}

eResult generation::fwstate_synchronization_update(const common::idp::updateGlobalBase::fwstate_synchronization_update::request& request)
{
	std::map<common::ipv6_address_t, tAclId> fw_state_multicast_acl_ids;

	for (const auto& v : request)
	{
		const auto& [aclId, ipv6SourceAddress, multicastIpv6Address, unicastIpv6SourceAddress, unicastIpv6Address, multicastDestinationPort, unicastDestinationPort, flows, ingressFlow] = v;
		fw_state_sync_config_t config{};

		if (!multicastIpv6Address.is_multicast())
		{
			return eResult::invalidMulticastIPv6Address;
		}

		const std::array<uint8_t, 16>& multicastIpv6AddressArray = multicastIpv6Address;

		// RFC2464.
		config.ether_address_destination.addr_bytes[0] = 0x33;
		config.ether_address_destination.addr_bytes[1] = 0x33;
		config.ether_address_destination.addr_bytes[2] = multicastIpv6AddressArray[12];
		config.ether_address_destination.addr_bytes[3] = multicastIpv6AddressArray[13];
		config.ether_address_destination.addr_bytes[4] = multicastIpv6AddressArray[14];
		config.ether_address_destination.addr_bytes[5] = multicastIpv6AddressArray[15];

		config.ipv6_address_source = ipv6_address_t::convert(ipv6SourceAddress);
		config.ipv6_address_multicast = ipv6_address_t::convert(multicastIpv6Address);
		config.ipv6_address_unicast_source = ipv6_address_t::convert(unicastIpv6SourceAddress);
		config.ipv6_address_unicast = ipv6_address_t::convert(unicastIpv6Address);
		config.port_multicast = rte_cpu_to_be_16(multicastDestinationPort);
		config.port_unicast = rte_cpu_to_be_16(unicastDestinationPort);
		config.flows_size = flows.size();
		config.ingress_flow = ingressFlow;
		for (unsigned int id = 0; id < flows.size(); id++)
		{
			config.flows[id] = flows[id];
		}

		fw_state_sync_configs[aclId] = config;
		fw_state_multicast_acl_ids.emplace(multicastIpv6Address, aclId);
	}

	std::lock_guard<std::mutex> lock(dataPlane->controlPlane->fw_state_multicast_acl_ids_mutex);
	std::swap(dataPlane->controlPlane->fw_state_multicast_acl_ids, fw_state_multicast_acl_ids);

	return eResult::success;
}
