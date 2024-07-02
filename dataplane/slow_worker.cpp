#include "slow_worker.h"

#include "common/fallback.h"
#include "dataplane.h"
#include "icmp_translations.h"
#include "prepare.h"

namespace dataplane
{
SlowWorker::SlowWorker(cWorker* worker,
                       std::vector<tPortId>&& ports_to_service,
                       std::vector<cWorker*>&& workers_to_service,
                       std::vector<dpdk::RingConn<rte_mbuf*>>&& from_gcs,
                       KernelInterfaceWorker&& kni,
                       rte_mempool* mempool,
                       bool use_kni,
                       uint32_t sw_icmp_out_rate_limit) :
        ports_serviced_{std::move(ports_to_service)},
        workers_serviced_{std::move(workers_to_service)},
        from_gcs_{std::move(from_gcs)},
        slow_worker_{worker},
        mempool_{mempool},
        fragmentation_(
                SlowWorkerSender(),
                slow_worker_->dataPlane->getConfigValues().fragmentation),
        dregress_(this,
                  slow_worker_->dataPlane,
                  static_cast<uint32_t>(slow_worker_->dataPlane->getConfigValues().gc_step)), // @TODO fix mismatch in type of config value and actually used one
        config_{sw_icmp_out_rate_limit, use_kni},
        kni_worker_{std::move(kni)}
{
	workers_serviced_.emplace_back(slow_worker_);
}

SlowWorker::SlowWorker(SlowWorker&& other) :
        ports_serviced_{std::move(other.ports_serviced_)},
        workers_serviced_{std::move(other.workers_serviced_)},
        slow_worker_{other.slow_worker_},
        mempool_{other.mempool_},
        fragmentation_{std::move(other.fragmentation_)},
        dregress_{std::move(other.dregress_)},
        kni_worker_{std::move(other.kni_worker_)}
{
	fragmentation_.Callback() = SlowWorkerSender();
}

SlowWorker& SlowWorker::operator=(SlowWorker&& other)
{
	ports_serviced_ = std::move(other.ports_serviced_);
	workers_serviced_ = std::move(other.workers_serviced_);
	slow_worker_ = other.slow_worker_;
	mempool_ = other.mempool_;
	fragmentation_ = std::move(other.fragmentation_);
	fragmentation_.Callback() = SlowWorkerSender();
	dregress_ = std::move(other.dregress_);
	kni_worker_ = std::move(other.kni_worker_);
	return *this;
}

void SlowWorker::freeWorkerPacket(rte_ring* ring_to_free_mbuf,
                                  rte_mbuf* mbuf)
{
	if (ring_to_free_mbuf == slow_worker_->ring_toFreePackets)
	{
		rte_pktmbuf_free(mbuf);
		return;
	}

	while (rte_ring_sp_enqueue(ring_to_free_mbuf, mbuf) != 0)
	{
		std::this_thread::yield();
	}
}

rte_mbuf* SlowWorker::convertMempool(rte_ring* ring_to_free_mbuf, rte_mbuf* old_mbuf)
{
	/// we dont support attached mbufs

	rte_mbuf* mbuf = rte_pktmbuf_alloc(mempool_);
	if (!mbuf)
	{
		stats_.mempool_is_empty++;

		freeWorkerPacket(ring_to_free_mbuf, old_mbuf);
		return nullptr;
	}

	*YADECAP_METADATA(mbuf) = *YADECAP_METADATA(old_mbuf);

	/// @todo: rte_pktmbuf_append() and check error

	memcpy(rte_pktmbuf_mtod(mbuf, char*),
	       rte_pktmbuf_mtod(old_mbuf, char*),
	       old_mbuf->data_len);

	mbuf->data_len = old_mbuf->data_len;
	mbuf->pkt_len = old_mbuf->pkt_len;

	freeWorkerPacket(ring_to_free_mbuf, old_mbuf);

	if (rte_mbuf_refcnt_read(mbuf) != 1)
	{
		YADECAP_LOG_ERROR("something wrong\n");
	}

	return mbuf;
}

void SlowWorker::SendToSlowWorker(rte_mbuf* mbuf, const common::globalBase::tFlow& flow)
{
	/// we dont support attached mbufs

	if (slow_worker_mbufs_.size() >= 1024) ///< @todo: variable
	{
		stats_.slowworker_drops++;
		rte_pktmbuf_free(mbuf);
		return;
	}

	stats_.slowworker_packets++;
	slow_worker_mbufs_.emplace(mbuf, flow);
}

unsigned SlowWorker::ring_handle(rte_ring* ring_to_free_mbuf,
                                 rte_ring* ring)
{
	rte_mbuf* mbufs[CONFIG_YADECAP_MBUFS_BURST_SIZE];

	unsigned rxSize = rte_ring_sc_dequeue_burst(ring,
	                                            (void**)mbufs,
	                                            CONFIG_YADECAP_MBUFS_BURST_SIZE,
	                                            nullptr);

#ifdef CONFIG_YADECAP_AUTOTEST
	if (rxSize)
	{
		std::this_thread::sleep_for(std::chrono::microseconds{400});
	}
#endif // CONFIG_YADECAP_AUTOTEST

	for (uint16_t mbuf_i = 0; mbuf_i < rxSize; mbuf_i++)
	{
		rte_mbuf* mbuf = convertMempool(ring_to_free_mbuf, mbufs[mbuf_i]);
		if (!mbuf)
		{
			continue;
		}

		dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

		if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_ingress_icmp)
		{
			handlePacket_icmp_translate_v6_to_v4(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_ingress_fragmentation)
		{
			metadata->flow.type = common::globalBase::eFlowType::nat64stateless_ingress_checked;
			handlePacket_fragment(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_egress_icmp)
		{
			handlePacket_icmp_translate_v4_to_v6(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_egress_fragmentation)
		{
			metadata->flow.type = common::globalBase::eFlowType::nat64stateless_egress_checked;
			handlePacket_fragment(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_dregress)
		{
			handlePacket_dregress(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_nat64stateless_egress_farm)
		{
			handlePacket_farm(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_dump)
		{
			kni_worker_.HandlePacketDump(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_repeat)
		{
			handlePacket_repeat(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_fw_sync)
		{
			handlePacket_fw_state_sync(mbuf);
		}
		else if (metadata->flow.type == common::globalBase::eFlowType::slowWorker_balancer_icmp_forward)
		{
			handlePacket_balancer_icmp_forward(mbuf);
		}
		else
		{
			handlePacketFromForwardingPlane(mbuf);
		}
	}
	return rxSize;
}

void SlowWorker::handlePacket_icmp_translate_v6_to_v4(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slow_worker_->current_base();
	const auto& nat64stateless = base.globalBase->nat64statelesses[metadata->flow.data.nat64stateless.id];
	const auto& translation = base.globalBase->nat64statelessTranslations[metadata->flow.data.nat64stateless.translationId];

	slow_worker_->slowWorkerTranslation(mbuf, nat64stateless, translation, true);

	if (do_icmp_translate_v6_to_v4(mbuf, translation))
	{
		slow_worker_->Stats().nat64stateless_ingressPackets++;
		SendToSlowWorker(mbuf, nat64stateless.flow);
	}
	else
	{
		slow_worker_->Stats().nat64stateless_ingressUnknownICMP++;
		rte_pktmbuf_free(mbuf);
	}
}

void SlowWorker::handlePacket_icmp_translate_v4_to_v6(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slow_worker_->current_base();
	const auto& nat64stateless = base.globalBase->nat64statelesses[metadata->flow.data.nat64stateless.id];
	const auto& translation = base.globalBase->nat64statelessTranslations[metadata->flow.data.nat64stateless.translationId];

	slow_worker_->slowWorkerTranslation(mbuf, nat64stateless, translation, false);

	if (do_icmp_translate_v4_to_v6(mbuf, translation))
	{
		slow_worker_->Stats().nat64stateless_egressPackets++;
		SendToSlowWorker(mbuf, nat64stateless.flow);
	}
	else
	{
		slow_worker_->Stats().nat64stateless_egressUnknownICMP++;
		rte_pktmbuf_free(mbuf);
	}
}

void SlowWorker::handlePacket_fragment(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slow_worker_->current_base();
	const auto& nat64stateless = base.globalBase->nat64statelesses[metadata->flow.data.nat64stateless.id];

	if (nat64stateless.defrag_farm_prefix.empty() || metadata->network_headerType != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) || nat64stateless.farm)
	{
		fragmentation_.insert(mbuf);
		return;
	}

	stats_.tofarm_packets++;
	slow_worker_->slowWorkerHandleFragment(mbuf);
	SendToSlowWorker(mbuf, nat64stateless.flow);
}

void SlowWorker::handlePacket_dregress(rte_mbuf* mbuf)
{
	dregress_.insert(mbuf);
}

void SlowWorker::handlePacket_farm(rte_mbuf* mbuf)
{
	stats_.farm_packets++;
	slow_worker_->slowWorkerFarmHandleFragment(mbuf);
}

void SlowWorker::handlePacket_repeat(rte_mbuf* mbuf)
{
	const rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, rte_ether_hdr*);
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	if (ethernetHeader->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
	{
		const rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf, rte_vlan_hdr*, sizeof(rte_ether_hdr));

		metadata->flow.data.logicalPortId = CALCULATE_LOGICALPORT_ID(metadata->fromPortId, rte_be_to_cpu_16(vlanHeader->vlan_tci));
	}
	else
	{
		metadata->flow.data.logicalPortId = CALCULATE_LOGICALPORT_ID(metadata->fromPortId, 0);
	}

	/// @todo: opt
	slow_worker_->preparePacket(mbuf);

	const auto& base = slow_worker_->current_base();
	const auto& logicalPort = base.globalBase->logicalPorts[metadata->flow.data.logicalPortId];

	stats_.repeat_packets++;
	SendToSlowWorker(mbuf, logicalPort.flow);
}

void SlowWorker::handlePacket_fw_state_sync(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = slow_worker_->current_base();
	const auto& fw_state_config = base.globalBase->fw_state_sync_configs[metadata->flow.data.aclId];

	metadata->network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	metadata->network_headerOffset = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr);
	metadata->transport_headerType = IPPROTO_UDP;
	metadata->transport_headerOffset = metadata->network_headerOffset + sizeof(rte_ipv6_hdr);

	generic_rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, generic_rte_ether_hdr*);
	ethernetHeader->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
	rte_ether_addr_copy(&fw_state_config.ether_address_destination, &ethernetHeader->dst_addr);

	rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf, rte_vlan_hdr*, sizeof(rte_ether_hdr));
	vlanHeader->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
	ipv6Header->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
	ipv6Header->payload_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + sizeof(dataplane::globalBase::fw_state_sync_frame_t));
	ipv6Header->proto = IPPROTO_UDP;
	ipv6Header->hop_limits = 64;
	memcpy(ipv6Header->src_addr, fw_state_config.ipv6_address_source.bytes, 16);
	memcpy(ipv6Header->dst_addr, fw_state_config.ipv6_address_multicast.bytes, 16);

	rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, metadata->network_headerOffset + sizeof(rte_ipv6_hdr));
	udpHeader->src_port = fw_state_config.port_multicast; // IPFW reuses the same port for both src and dst.
	udpHeader->dst_port = fw_state_config.port_multicast;
	udpHeader->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + sizeof(dataplane::globalBase::fw_state_sync_frame_t));
	udpHeader->dgram_cksum = 0;
	udpHeader->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6Header, udpHeader);

	// Iterate for all interested ports.
	for (unsigned int port_id = 0; port_id < fw_state_config.flows_size; port_id++)
	{
		rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool_);
		if (mbuf_clone == nullptr)
		{
			slow_worker_->Stats().fwsync_multicast_egress_drops++;
			continue;
		}

		*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);

		memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
		       rte_pktmbuf_mtod(mbuf, char*),
		       mbuf->data_len);
		mbuf_clone->data_len = mbuf->data_len;
		mbuf_clone->pkt_len = mbuf->pkt_len;

		const auto& flow = fw_state_config.flows[port_id];
		slow_worker_->Stats().fwsync_multicast_egress_packets++;
		SendToSlowWorker(mbuf_clone, flow);
	}

	if (!fw_state_config.ipv6_address_unicast.empty())
	{
		memcpy(ipv6Header->src_addr, fw_state_config.ipv6_address_unicast_source.bytes, 16);
		memcpy(ipv6Header->dst_addr, fw_state_config.ipv6_address_unicast.bytes, 16);
		udpHeader->src_port = fw_state_config.port_unicast;
		udpHeader->dst_port = fw_state_config.port_unicast;
		udpHeader->dgram_cksum = 0;
		udpHeader->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6Header, udpHeader);

		rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool_);
		if (mbuf_clone == nullptr)
		{
			slow_worker_->Stats().fwsync_unicast_egress_drops++;
		}
		else
		{
			*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);

			memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
			       rte_pktmbuf_mtod(mbuf, char*),
			       mbuf->data_len);
			mbuf_clone->data_len = mbuf->data_len;
			mbuf_clone->pkt_len = mbuf->pkt_len;

			slow_worker_->Stats().fwsync_unicast_egress_packets++;
			SendToSlowWorker(mbuf_clone, fw_state_config.ingress_flow);
		}
	}

	rte_pktmbuf_free(mbuf);
}

bool SlowWorker::handlePacket_fw_state_sync_ingress(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	generic_rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, generic_rte_ether_hdr*);
	if ((ethernetHeader->dst_addr.addr_bytes[0] & 1) == 0)
	{
		return false;
	}

	// Confirmed multicast packet.
	// Try to match against our multicast groups.
	if (ethernetHeader->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
	{
		return false;
	}

	rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf, rte_vlan_hdr*, sizeof(rte_ether_hdr));
	if (vlanHeader->eth_proto != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		return false;
	}

	rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr));
	if (metadata->transport_headerType != IPPROTO_UDP)
	{
		return false;
	}

	const auto udp_payload_len = rte_be_to_cpu_16(ipv6Header->payload_len) - sizeof(rte_udp_hdr);
	// Can contain multiple states per sync packet.
	if (udp_payload_len % sizeof(dataplane::globalBase::fw_state_sync_frame_t) != 0)
	{
		return false;
	}

	tAclId aclId;
	if (!slow_worker_->dataPlane->controlPlane->fw_state_multicast_acl_ids.apply([&](auto& fw_state_multicast_acl_ids) {
		    auto it = fw_state_multicast_acl_ids.find(common::ipv6_address_t(ipv6Header->dst_addr));
		    if (it == fw_state_multicast_acl_ids.end())
		    {
			    return false;
		    }
		    aclId = it->second;
		    return true;
	    }))
	{
		return false;
	}

	const auto& base = slow_worker_->current_base();
	const auto& fw_state_config = base.globalBase->fw_state_sync_configs[aclId];

	if (memcmp(ipv6Header->src_addr, fw_state_config.ipv6_address_source.bytes, 16) == 0)
	{
		// Ignore self-generated packets.
		return false;
	}

	rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + sizeof(rte_ipv6_hdr));
	if (udpHeader->dst_port != fw_state_config.port_multicast)
	{
		return false;
	}

	for (size_t idx = 0; idx < udp_payload_len / sizeof(dataplane::globalBase::fw_state_sync_frame_t); ++idx)
	{
		dataplane::globalBase::fw_state_sync_frame_t* payload = rte_pktmbuf_mtod_offset(
		        mbuf,
		        dataplane::globalBase::fw_state_sync_frame_t*,
		        sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + idx * sizeof(dataplane::globalBase::fw_state_sync_frame_t));

		if (payload->addr_type == 6)
		{
			dataplane::globalBase::fw6_state_key_t key;
			key.proto = payload->proto;
			key.__nap = 0;
			// Swap src and dst addresses.
			memcpy(key.dst_addr.bytes, payload->src_ip6.bytes, 16);
			memcpy(key.src_addr.bytes, payload->dst_ip6.bytes, 16);

			if (payload->proto == IPPROTO_TCP || payload->proto == IPPROTO_UDP)
			{
				// Swap src and dst ports.
				key.dst_port = payload->src_port;
				key.src_port = payload->dst_port;
			}
			else
			{
				key.dst_port = 0;
				key.src_port = 0;
			}

			dataplane::globalBase::fw_state_value_t value;
			value.type = static_cast<dataplane::globalBase::fw_state_type>(payload->proto);
			value.owner = dataplane::globalBase::fw_state_owner_e::external;
			value.last_seen = slow_worker_->CurrentTime();
			value.flow = fw_state_config.ingress_flow;
			value.acl_id = aclId;
			value.last_sync = slow_worker_->CurrentTime();
			value.packets_since_last_sync = 0;
			value.packets_backward = 0;
			value.packets_forward = 0;
			value.tcp.unpack(payload->flags);

			auto& dataPlane = slow_worker_->dataPlane;
			uint32_t state_timeout = dataPlane->getConfigValues().stateful_firewall_other_protocols_timeout;
			if (payload->proto == IPPROTO_UDP)
			{
				state_timeout = dataPlane->getConfigValues().stateful_firewall_udp_timeout;
			}
			else if (payload->proto == IPPROTO_TCP)
			{
				state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_timeout;
				uint8_t flags = value.tcp.src_flags | value.tcp.dst_flags;
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::ACK)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_syn_ack_timeout;
				}
				else if (flags & (uint8_t)common::fwstate::tcp_flags_e::SYN)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_syn_timeout;
				}
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::FIN)
				{
					state_timeout = dataPlane->getConfigValues().stateful_firewall_tcp_fin_timeout;
				}
			}
			value.state_timeout = state_timeout;

			for (auto& [socketId, globalBaseAtomic] : slow_worker_->dataPlane->globalBaseAtomics)
			{
				(void)socketId;

				dataplane::globalBase::fw_state_value_t* lookup_value;
				dataplane::spinlock_nonrecursive_t* locker;
				const uint32_t hash = globalBaseAtomic->fw6_state->lookup(key, lookup_value, locker);
				if (lookup_value)
				{
					// Keep state alive for us even if there were no packets received.
					// Do not reset other counters.
					lookup_value->last_seen = slow_worker_->CurrentTime();
					lookup_value->tcp.src_flags |= value.tcp.src_flags;
					lookup_value->tcp.dst_flags |= value.tcp.dst_flags;
					lookup_value->state_timeout = std::max(lookup_value->state_timeout, value.state_timeout);
				}
				else
				{
					globalBaseAtomic->fw6_state->insert(hash, key, value);
				}
				locker->unlock();
			}
		}
		else if (payload->addr_type == 4)
		{
			dataplane::globalBase::fw4_state_key_t key;
			key.proto = payload->proto;
			key.__nap = 0;
			// Swap src and dst addresses.
			key.dst_addr.address = payload->src_ip;
			key.src_addr.address = payload->dst_ip;

			if (payload->proto == IPPROTO_TCP || payload->proto == IPPROTO_UDP)
			{
				// Swap src and dst ports.
				key.dst_port = payload->src_port;
				key.src_port = payload->dst_port;
			}
			else
			{
				key.dst_port = 0;
				key.src_port = 0;
			}

			dataplane::globalBase::fw_state_value_t value;
			value.type = static_cast<dataplane::globalBase::fw_state_type>(payload->proto);
			value.owner = dataplane::globalBase::fw_state_owner_e::external;
			value.last_seen = slow_worker_->CurrentTime();
			value.flow = fw_state_config.ingress_flow;
			value.acl_id = aclId;
			value.last_sync = slow_worker_->CurrentTime();
			value.packets_since_last_sync = 0;
			value.packets_backward = 0;
			value.packets_forward = 0;
			value.tcp.unpack(payload->flags);

			auto& cfg = slow_worker_->dataPlane->getConfigValues();
			uint32_t state_timeout = cfg.stateful_firewall_other_protocols_timeout;
			if (payload->proto == IPPROTO_UDP)
			{
				state_timeout = cfg.stateful_firewall_udp_timeout;
			}
			else if (payload->proto == IPPROTO_TCP)
			{
				state_timeout = cfg.stateful_firewall_tcp_timeout;
				uint8_t flags = value.tcp.src_flags | value.tcp.dst_flags;
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::ACK)
				{
					state_timeout = cfg.stateful_firewall_tcp_syn_ack_timeout;
				}
				else if (flags & (uint8_t)common::fwstate::tcp_flags_e::SYN)
				{
					state_timeout = cfg.stateful_firewall_tcp_syn_timeout;
				}
				if (flags & (uint8_t)common::fwstate::tcp_flags_e::FIN)
				{
					state_timeout = cfg.stateful_firewall_tcp_fin_timeout;
				}
			}
			value.state_timeout = state_timeout;

			for (auto& [socketId, globalBaseAtomic] : slow_worker_->dataPlane->globalBaseAtomics)
			{
				(void)socketId;

				dataplane::globalBase::fw_state_value_t* lookup_value;
				dataplane::spinlock_nonrecursive_t* locker;
				const uint32_t hash = globalBaseAtomic->fw4_state->lookup(key, lookup_value, locker);
				if (lookup_value)
				{
					// Keep state alive for us even if there were no packets received.
					// Do not reset other counters.
					lookup_value->last_seen = slow_worker_->CurrentTime();
					lookup_value->tcp.src_flags |= value.tcp.src_flags;
					lookup_value->tcp.dst_flags |= value.tcp.dst_flags;
					lookup_value->state_timeout = std::max(lookup_value->state_timeout, value.state_timeout);
				}
				else
				{
					globalBaseAtomic->fw4_state->insert(hash, key, value);
				}
				locker->unlock();
			}
		}
	}

	return true;
}

void SlowWorker::BalancerICMPForwardCriticalSection(
        rte_mbuf* mbuf,
        cControlPlane::VipToBalancers& vip_to_balancers,
        cControlPlane::VipVportProto& vip_vport_proto)
{
	const auto& base = slow_worker_->current_base();

	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	common::ip_address_t original_src_from_icmp_payload;
	common::ip_address_t src_from_ip_header;
	uint16_t original_src_port_from_icmp_payload;

	uint32_t balancer_id = metadata->flow.data.balancer.id;

	dataplane::metadata inner_metadata;

	if (metadata->transport_headerType == IPPROTO_ICMP)
	{
		rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
		src_from_ip_header = common::ip_address_t(rte_be_to_cpu_32(ipv4Header->src_addr));

		rte_ipv4_hdr* icmpPayloadIpv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->transport_headerOffset + sizeof(icmpv4_header_t));
		original_src_from_icmp_payload = common::ip_address_t(rte_be_to_cpu_32(icmpPayloadIpv4Header->src_addr));

		inner_metadata.network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		inner_metadata.network_headerOffset = metadata->transport_headerOffset + sizeof(icmpv4_header_t);
	}
	else
	{
		rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
		src_from_ip_header = common::ip_address_t(ipv6Header->src_addr);

		rte_ipv6_hdr* icmpPayloadIpv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->transport_headerOffset + sizeof(icmpv6_header_t));
		original_src_from_icmp_payload = common::ip_address_t(icmpPayloadIpv6Header->src_addr);

		inner_metadata.network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		inner_metadata.network_headerOffset = metadata->transport_headerOffset + sizeof(icmpv6_header_t);
	}

	if (!prepareL3(mbuf, &inner_metadata))
	{
		/* we are not suppossed to get in here anyway, same check was done earlier by balancer_icmp_forward_handle(),
		   but we needed to call prepareL3() to determine icmp payload original packets transport header offset */
		if (inner_metadata.network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		{
			slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_drop_icmpv4_payload_too_short_ip);
		}
		else
		{
			slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_drop_icmpv6_payload_too_short_ip);
		}

		return;
	}

	if (inner_metadata.transport_headerType != IPPROTO_TCP && inner_metadata.transport_headerType != IPPROTO_UDP)
	{
		// not supported protocol for cloning and distributing, drop
		slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_drop_unexpected_transport_protocol);
		return;
	}

	// check whether ICMP payload is too short to contain "offending" packet's IP header and ports is performed earlier by balancer_icmp_forward_handle()
	void* icmpPayloadTransportHeader = rte_pktmbuf_mtod_offset(mbuf, void*, inner_metadata.transport_headerOffset);

	// both TCP and UDP headers have src port (16 bits) as the first field
	original_src_port_from_icmp_payload = rte_be_to_cpu_16(*(uint16_t*)icmpPayloadTransportHeader);

	if (vip_to_balancers.size() <= balancer_id)
	{
		// no vip_to_balancers table for this balancer_id
		slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_drop_no_unrdup_table_for_balancer_id);
		return;
	}

	if (!vip_to_balancers[balancer_id].count(original_src_from_icmp_payload))
	{
		// vip is not listed in unrdup config - neighbor balancers are unknown, drop
		slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_drop_unrdup_vip_not_found);
		return;
	}

	if (vip_vport_proto.size() <= balancer_id)
	{
		// no vip_vport_proto table for this balancer_id
		slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id);
		return;
	}

	if (!vip_vport_proto[balancer_id].count({original_src_from_icmp_payload, original_src_port_from_icmp_payload, inner_metadata.transport_headerType}))
	{
		// such combination of vip-vport-protocol is absent, don't clone, drop
		slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_drop_unknown_service);
		return;
	}

	const auto& neighbor_balancers = vip_to_balancers[balancer_id][original_src_from_icmp_payload];

	for (const auto& neighbor_balancer : neighbor_balancers)
	{
		// will not send a cloned packet if source address in "balancer" section of controlplane.conf is absent
		if (neighbor_balancer.is_ipv4() && !base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv4.address)
		{
			slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_no_balancer_src_ipv4);
			continue;
		}

		if (neighbor_balancer.is_ipv6() && base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv6.empty())
		{
			slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_no_balancer_src_ipv6);
			continue;
		}

		rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool_);
		if (mbuf_clone == nullptr)
		{
			slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_failed_to_clone);
			continue;
		}

		*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);
		dataplane::metadata* clone_metadata = YADECAP_METADATA(mbuf_clone);

		rte_memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
		           rte_pktmbuf_mtod(mbuf, char*),
		           mbuf->data_len);

		if (neighbor_balancer.is_ipv4())
		{
			rte_pktmbuf_prepend(mbuf_clone, sizeof(rte_ipv4_hdr));
			memmove(rte_pktmbuf_mtod(mbuf_clone, char*),
			        rte_pktmbuf_mtod_offset(mbuf_clone, char*, sizeof(rte_ipv4_hdr)),
			        clone_metadata->network_headerOffset);

			rte_ipv4_hdr* outerIpv4Header = rte_pktmbuf_mtod_offset(mbuf_clone, rte_ipv4_hdr*, clone_metadata->network_headerOffset);

			outerIpv4Header->src_addr = base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv4.address;
			outerIpv4Header->dst_addr = rte_cpu_to_be_32(neighbor_balancer.get_ipv4());

			outerIpv4Header->version_ihl = 0x45;
			outerIpv4Header->type_of_service = 0x00;
			outerIpv4Header->packet_id = rte_cpu_to_be_16(0x01);
			outerIpv4Header->fragment_offset = 0;
			outerIpv4Header->time_to_live = 64;

			outerIpv4Header->total_length = rte_cpu_to_be_16((uint16_t)(mbuf->pkt_len - clone_metadata->network_headerOffset + sizeof(rte_ipv4_hdr)));

			if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			{
				outerIpv4Header->next_proto_id = IPPROTO_IPIP;
			}
			else
			{
				outerIpv4Header->next_proto_id = IPPROTO_IPV6;
			}

			yanet_ipv4_checksum(outerIpv4Header);

			mbuf_clone->data_len = mbuf->data_len + sizeof(rte_ipv4_hdr);
			mbuf_clone->pkt_len = mbuf->pkt_len + sizeof(rte_ipv4_hdr);

			// might need to change next protocol type in ethernet/vlan header in cloned packet

			rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf_clone, rte_ether_hdr*);
			if (ethernetHeader->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
			{
				rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf_clone, rte_vlan_hdr*, sizeof(rte_ether_hdr));
				vlanHeader->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
			}
			else
			{
				ethernetHeader->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
			}
		}
		else if (neighbor_balancer.is_ipv6())
		{
			rte_pktmbuf_prepend(mbuf_clone, sizeof(rte_ipv6_hdr));
			memmove(rte_pktmbuf_mtod(mbuf_clone, char*),
			        rte_pktmbuf_mtod_offset(mbuf_clone, char*, sizeof(rte_ipv6_hdr)),
			        clone_metadata->network_headerOffset);

			rte_ipv6_hdr* outerIpv6Header = rte_pktmbuf_mtod_offset(mbuf_clone, rte_ipv6_hdr*, clone_metadata->network_headerOffset);

			rte_memcpy(outerIpv6Header->src_addr, base.globalBase->balancers[metadata->flow.data.balancer.id].source_ipv6.bytes, sizeof(outerIpv6Header->src_addr));
			if (src_from_ip_header.is_ipv6())
			{
				((uint32_t*)outerIpv6Header->src_addr)[2] = ((uint32_t*)src_from_ip_header.get_ipv6().data())[2] ^ ((uint32_t*)src_from_ip_header.get_ipv6().data())[3];
			}
			else
			{
				((uint32_t*)outerIpv6Header->src_addr)[2] = src_from_ip_header.get_ipv4();
			}
			rte_memcpy(outerIpv6Header->dst_addr, neighbor_balancer.get_ipv6().data(), sizeof(outerIpv6Header->dst_addr));

			outerIpv6Header->vtc_flow = rte_cpu_to_be_32((0x6 << 28));
			outerIpv6Header->payload_len = rte_cpu_to_be_16((uint16_t)(mbuf->pkt_len - clone_metadata->network_headerOffset));
			outerIpv6Header->hop_limits = 64;

			if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			{
				outerIpv6Header->proto = IPPROTO_IPIP;
			}
			else
			{
				outerIpv6Header->proto = IPPROTO_IPV6;
			}

			mbuf_clone->data_len = mbuf->data_len + sizeof(rte_ipv6_hdr);
			mbuf_clone->pkt_len = mbuf->pkt_len + sizeof(rte_ipv6_hdr);

			// might need to change next protocol type in ethernet/vlan header in cloned packet

			rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf_clone, rte_ether_hdr*);
			if (ethernetHeader->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
			{
				rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf_clone, rte_vlan_hdr*, sizeof(rte_ether_hdr));
				vlanHeader->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
			}
			else
			{
				ethernetHeader->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
			}
		}

		slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_clone_forwarded);

		const auto& flow = base.globalBase->balancers[metadata->flow.data.balancer.id].flow;

		slow_worker_->preparePacket(mbuf_clone);
		SendToSlowWorker(mbuf_clone, flow);
	}
}

void SlowWorker::handlePacket_balancer_icmp_forward(rte_mbuf* mbuf)
{
	if (config_.SWICMPOutRateLimit != 0)
	{
		if (icmp_out_remainder_ == 0)
		{
			slow_worker_->IncrementCounter(common::globalBase::static_counter_type::balancer_icmp_out_rate_limit_reached);
			rte_pktmbuf_free(mbuf);
			return;
		}

		--icmp_out_remainder_;
	}

	slow_worker_->dataPlane->controlPlane->vip_to_balancers.apply([&](auto& vip_to_balancers) {
		slow_worker_->dataPlane->controlPlane->vip_vport_proto.apply([&](auto& vip_vport_proto) {
			BalancerICMPForwardCriticalSection(mbuf, vip_to_balancers, vip_vport_proto);
		});
	});

	// packet itself is not going anywhere, only its clones with prepended header
	rte_pktmbuf_free(mbuf);
}

void SlowWorker::handlePacketFromForwardingPlane(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	if (handlePacket_fw_state_sync_ingress(mbuf))
	{
		stats_.fwsync_multicast_ingress_packets++;
		rte_pktmbuf_free(mbuf);
		return;
	}

#ifdef CONFIG_YADECAP_AUTOTEST
	if (metadata->flow.type != common::globalBase::eFlowType::slowWorker_kni_local)
	{
		// drop by default in tests
		stats_.slowworker_drops++;
		rte_pktmbuf_free(mbuf);
		return;
	}
	rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, rte_ether_hdr*);
	memset(ethernetHeader->dst_addr.addr_bytes,
	       0x71,
	       6);

#endif

	if (!config_.use_kernel_interface)
	{
		// TODO stats
		unsigned txSize = rte_eth_tx_burst(metadata->fromPortId, 0, &mbuf, 1);
		if (!txSize)
		{
			rte_pktmbuf_free(mbuf);
		}
		return;
	}
	else
	{
		kni_worker_.HandlePacketFromForwardingPlane(mbuf);
	}
}

void SlowWorker::HandleWorkerRings()
{
	for (unsigned nIter = 0; nIter < YANET_CONFIG_RING_PRIORITY_RATIO; nIter++)
	{
		for (unsigned hIter = 0; hIter < YANET_CONFIG_RING_PRIORITY_RATIO; hIter++)
		{
			unsigned hProcessed = 0;
			for (cWorker* worker : workers_serviced_)
			{
				hProcessed += ring_handle(worker->ring_toFreePackets, worker->ring_highPriority);
			}
			if (!hProcessed)
			{
				break;
			}
		}

		unsigned nProcessed = 0;
		for (cWorker* worker : workers_serviced_)
		{
			nProcessed += ring_handle(worker->ring_toFreePackets, worker->ring_normalPriority);
		}
		if (!nProcessed)
		{
			break;
		}
	}
	for (cWorker* worker : workers_serviced_)
	{
		ring_handle(worker->ring_toFreePackets, worker->ring_lowPriority);
	}
}

void SlowWorker::DequeueGC()
{
	for (auto& [process, free] : from_gcs_)
	{
		rte_mbuf* mbufs[CONFIG_YADECAP_MBUFS_BURST_SIZE];

		unsigned rxSize = process.DequeueBurstSC(mbufs);

		for (uint16_t mbuf_i = 0; mbuf_i < rxSize; mbuf_i++)
		{
			rte_mbuf* mbuf = convertMempool(free._Underlying(), mbufs[mbuf_i]);
			if (!mbuf)
			{
				continue;
			}

			dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

			SendToSlowWorker(mbuf, metadata->flow);
		}
	}
}

} // namespace dataplane
