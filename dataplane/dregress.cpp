#include <rte_tcp.h>
#include <rte_udp.h>

#include "common/fallback.h"

#include "checksum.h"
#include "controlplane.h"
#include "dregress.h"
#include "metadata.h"
#include "worker.h"

dregress_t::dregress_t(cControlPlane* controlplane,
                       cDataPlane* dataplane) :
        controlplane(controlplane),
        dataplane(dataplane)
{
	memset(&stats, 0, sizeof(stats));
	connections = new dataplane::hashtable_chain_spinlock_t<dregress::connection_key_t, dregress::connection_value_t, YANET_CONFIG_DREGRESS_HT_SIZE, YANET_CONFIG_DREGRESS_HT_EXTENDED_SIZE, 4, 4>();
}

dregress_t::~dregress_t()
{
	delete connections;
}

void dregress_t::insert(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const auto& base = controlplane->slowWorker->bases[controlplane->slowWorker->localBaseId & 1];
	const auto& dregress = base.globalBase->dregresses[metadata->flow.data.dregressId];

	if (metadata->network_flags & YANET_NETWORK_FLAG_FRAGMENT)
	{
		stats.fragment++;

		controlplane->sendPacketToSlowWorker(mbuf, dregress.flow);
		return;
	}

	if (metadata->transport_headerType != IPPROTO_TCP)
	{
		stats.bad_transport++;

		controlplane->sendPacketToSlowWorker(mbuf, dregress.flow);
		return;
	}

	rte_tcp_hdr* tcpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);

	ipv6_address_t labelled_nexthop;
	uint32_t labelled_label = 0;
	uint8_t mpls_ttl = 255;

	dregress::connection_key_t key;
	key.port_source = tcpHeader->src_port;
	key.port_destination = tcpHeader->dst_port;

	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		rte_ipv4_hdr* ipv4HeaderInner = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);

		memset(key.source.bytes, 0, 16);
		memset(key.destination.bytes, 0, 16);

		key.source.mapped_ipv4_address.address = ipv4HeaderInner->src_addr;
		key.destination.mapped_ipv4_address.address = ipv4HeaderInner->dst_addr;
	}
	else
	{
		rte_ipv6_hdr* ipv6HeaderInner = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);

		memcpy(key.source.bytes, ipv6HeaderInner->src_addr, 16);
		memcpy(key.destination.bytes, ipv6HeaderInner->dst_addr, 16);
	}

	if (tcpHeader->tcp_flags & TCP_SYN_FLAG)
	{
		connections->remove(key);

		auto direction = lookup(mbuf);
		if (!direction)
		{
			stats.lookup_miss++;

			controlplane->sendPacketToSlowWorker(mbuf, dregress.flow);
			return;
		}

		const auto& [prefix, nexthop, is_best, label, community, peer_as, origin_as] = *direction;
		(void)prefix;
		(void)is_best;
		(void)community;
		(void)peer_as;
		(void)origin_as;

		labelled_nexthop = ipv6_address_t::convert(nexthop);
		labelled_label = label;

		stats.tcp_syn++;
	}
	else
	{
		dregress::connection_value_t* value;
		dataplane::spinlock_t* locker;

		connections->lookup(key, value, locker);

		uint32_t loss_count;
		uint32_t ack_count;

		int32_t ack_diff = 0;
		int32_t loss_diff = 0;
		uint16_t rtt = 0;
		uint8_t rtt_count = 0;

		if (!value)
		{
			auto direction = lookup(mbuf);
			if (!direction)
			{
				stats.lookup_miss++;

				controlplane->sendPacketToSlowWorker(mbuf, dregress.flow);
				return;
			}

			const auto& [prefix, nexthop, is_best, label, community, peer_as, origin_as] = *direction;

			labelled_nexthop = ipv6_address_t::convert(nexthop);
			labelled_label = label;

			ipv6_address_t prefix_address;
			uint8_t prefix_mask;
			if (prefix.is_ipv4())
			{
				prefix_address = ipv6_address_t::convert(prefix.get_ipv4().address());
				prefix_mask = prefix.get_ipv4().mask();
			}
			else
			{
				prefix_address = ipv6_address_t::convert(prefix.get_ipv6().address());
				prefix_mask = prefix.get_ipv6().mask();
			}

			if (tcp_parse(mbuf, rtt, loss_count, ack_count))
			{
				stats.tcp_insert_sessions++;
				uint8_t flags = 0;

				if (is_best)
				{
					flags |= YANET_DREGRESS_FLAG_IS_BEST;
				}

				if (nexthop.is_ipv4())
				{
					flags |= YANET_DREGRESS_FLAG_NH_IS_IPV4;
				}

				connections->insert(key, {loss_count, ack_count, labelled_nexthop, label, community, prefix_address, peer_as, origin_as, (uint16_t)controlplane->currentTime, flags, prefix_mask});

				if (tcpHeader->tcp_flags & TCP_FIN_FLAG)
				{
					rtt_count = 1;
				}
				else
				{
					rtt = 0;
					rtt_count = 0;
				}

				std::lock_guard<std::mutex> guard(counters_mutex);
				if (prefix.is_ipv4())
				{
					counters_v4.append(community,
					                   nexthop,
					                   is_best,
					                   label,
					                   peer_as,
					                   origin_as,
					                   prefix,
					                   {0, 0, rtt, rtt_count});
				}
				else
				{
					counters_v6.append(community,
					                   nexthop,
					                   is_best,
					                   label,
					                   peer_as,
					                   origin_as,
					                   prefix,
					                   {0, 0, rtt, rtt_count});
				}
			}
		}
		else
		{
			if (tcp_parse(mbuf, rtt, loss_count, ack_count))
			{
				ack_diff = (int32_t)(ack_count - value->ack_count);
				loss_diff = (int32_t)(loss_count - value->loss_count);

				common::ip_prefix_t prefix;
				if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
				{
					prefix = common::ipv4_prefix_t(rte_be_to_cpu_32(value->prefix_address.mapped_ipv4_address.address),
					                               value->prefix_mask);
				}
				else
				{
					prefix = common::ipv6_prefix_t(value->prefix_address.bytes,
					                               value->prefix_mask);
				}

				if (ack_diff > 0)
				{
					stats.tcp_ok += ack_diff;
					mpls_ttl -= 1;
				}
				else
				{
					ack_diff = 0;
				}

				if (loss_diff > 0)
				{
					stats.tcp_retransmission += loss_diff;
					mpls_ttl -= 2;
				}
				else
				{
					loss_diff = 0;
				}

				value->loss_count = loss_count;
				value->ack_count = ack_count;

				if (tcpHeader->tcp_flags & TCP_FIN_FLAG)
				{
					rtt_count = 1;
				}
				else
				{
					rtt = 0;
					rtt_count = 0;
				}

				common::ip_address_t nexthop;
				if (value->flags & YANET_DREGRESS_FLAG_NH_IS_IPV4)
				{
					nexthop = common::ip_address_t(4, value->nexthop.bytes);
				}
				else
				{
					nexthop = common::ip_address_t(6, value->nexthop.bytes);
				}

				std::lock_guard<std::mutex> guard(counters_mutex);
				if (prefix.is_ipv4())
				{
					counters_v4.append(value->community,
					                   nexthop,
					                   value->flags & YANET_DREGRESS_FLAG_IS_BEST,
					                   value->label,
					                   value->peer_as,
					                   value->origin_as,
					                   prefix,
					                   {(uint64_t)ack_diff, (uint64_t)loss_diff, rtt, rtt_count});
				}
				else
				{
					counters_v6.append(value->community,
					                   nexthop,
					                   value->flags & YANET_DREGRESS_FLAG_IS_BEST,
					                   value->label,
					                   value->peer_as,
					                   value->origin_as,
					                   prefix,
					                   {(uint64_t)ack_diff, (uint64_t)loss_diff, rtt, rtt_count});
				}
			}

			labelled_nexthop = value->nexthop;
			labelled_label = value->label;

			value->timestamp = (uint16_t)controlplane->currentTime;

			if (tcpHeader->tcp_flags & (TCP_FIN_FLAG | TCP_RST_FLAG))
			{
				value->flags |= YANET_DREGRESS_FLAG_FIN;
			}

			locker->unlock();
		}
	}

	uint16_t payload_length;
	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		rte_ipv4_hdr* ipv4HeaderInner = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);

		/// @todo: mpls_header_t
		rte_pktmbuf_prepend(mbuf, sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE);
		memcpy(rte_pktmbuf_mtod(mbuf, char*),
		       rte_pktmbuf_mtod_offset(mbuf, char*, sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE),
		       metadata->network_headerOffset);

		/// @todo: check for ethernetHeader or vlanHeader
		uint16_t* nextHeaderType = rte_pktmbuf_mtod_offset(mbuf, uint16_t*, metadata->network_headerOffset - 2);
		*nextHeaderType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

		rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);

		ipv4Header->version_ihl = 0x45;
		ipv4Header->type_of_service = ipv4HeaderInner->type_of_service;
		ipv4Header->total_length = rte_cpu_to_be_16((sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE) + rte_be_to_cpu_16(ipv4HeaderInner->total_length));
		ipv4Header->packet_id = ipv4HeaderInner->packet_id;
		ipv4Header->fragment_offset = 0;
		ipv4Header->time_to_live = 64;
		ipv4Header->next_proto_id = IPPROTO_UDP;
		ipv4Header->hdr_checksum = 0;
		ipv4Header->src_addr = dregress.ipv4AddressSource.address;
		ipv4Header->dst_addr = labelled_nexthop.mapped_ipv4_address.address;

		yanet_ipv4_checksum(ipv4Header);

		metadata->transport_headerOffset = metadata->network_headerOffset + sizeof(rte_ipv4_hdr);

		payload_length = rte_be_to_cpu_16(ipv4HeaderInner->total_length);
	}
	else
	{
		rte_ipv6_hdr* ipv6HeaderInner = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);

		/// @todo: mpls_header_t
		rte_pktmbuf_prepend(mbuf, sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE);
		memcpy(rte_pktmbuf_mtod(mbuf, char*),
		       rte_pktmbuf_mtod_offset(mbuf, char*, sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE),
		       metadata->network_headerOffset);

		/// @todo: check for ethernetHeader or vlanHeader
		uint16_t* nextHeaderType = rte_pktmbuf_mtod_offset(mbuf, uint16_t*, metadata->network_headerOffset - 2);
		*nextHeaderType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

		rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);

		ipv6Header->vtc_flow = ipv6HeaderInner->vtc_flow;
		ipv6Header->payload_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE + sizeof(rte_ipv6_hdr) + rte_be_to_cpu_16(ipv6HeaderInner->payload_len));
		ipv6Header->proto = IPPROTO_UDP;
		ipv6Header->hop_limits = 64;
		memcpy(ipv6Header->src_addr, dregress.ipv6AddressSource.bytes, 16);
		memcpy(ipv6Header->dst_addr, labelled_nexthop.bytes, 16);

		metadata->transport_headerOffset = metadata->network_headerOffset + sizeof(rte_ipv6_hdr);

		payload_length = sizeof(rte_ipv6_hdr) + rte_be_to_cpu_16(ipv6HeaderInner->payload_len);
	}

	metadata->hash = rte_hash_crc(&metadata->flowLabel, 4, metadata->hash);

	{
		rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, metadata->transport_headerOffset);

		udpHeader->src_port = rte_cpu_to_be_16(metadata->hash | 0xC000u);
		udpHeader->dst_port = dregress.udpDestinationPort;
		udpHeader->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE + payload_length);
		udpHeader->dgram_cksum = 0;
	}

	{
		uint32_t* mplsHeaderTransport = rte_pktmbuf_mtod_offset(mbuf, uint32_t*, metadata->transport_headerOffset + sizeof(rte_udp_hdr));

		*mplsHeaderTransport = rte_cpu_to_be_32(((labelled_label & 0xFFFFF) << 12) | (1 << 8)) | (mpls_ttl << 24);
	}

	/// @todo: opt
	controlplane->slowWorker->preparePacket(mbuf);
	controlplane->sendPacketToSlowWorker(mbuf, dregress.flow);
}

void dregress_t::handle()
{
	/// gc
	for (auto& iter : connections->range(gc_step))
	{
		iter.lock();

		if (iter.isValid())
		{
			if (iter.value()->flags & YANET_DREGRESS_FLAG_FIN)
			{
				if ((uint16_t)(controlplane->currentTime - iter.value()->timestamp) > 8) ///< @todo: tag:DREGRESS_CONFIG
				{
					iter.unsetValid();

					stats.tcp_close_sessions++;
				}
			}
			else
			{
				if ((uint16_t)(controlplane->currentTime - iter.value()->timestamp) > 60) ///< @todo: tag:DREGRESS_CONFIG
				{
					iter.unsetValid();

					stats.tcp_timeout_sessions++;
				}
			}
		}

		iter.gc();

		iter.unlock();
	}
}

std::optional<dregress::direction_t> dregress_t::lookup(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	const auto& base = controlplane->slowWorker->bases[controlplane->slowWorker->localBaseId & 1];
	const auto& dregress = base.globalBase->dregresses[metadata->flow.data.dregressId];

	std::map<std::tuple<common::ip_address_t, ///< nexthop
	                    uint32_t>, ///< label
	         dregress::direction_t>
	        directions;

	uint8_t mask_max = 0;

	common::ip_prefix_t prefix;
	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
		common::ipv4_address_t address = rte_be_to_cpu_32(ipv4_header->dst_addr);
		prefix = common::ip_prefix_t(address, 32);
	}
	else
	{
		rte_ipv6_hdr* ipv6_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
		common::ipv6_address_t address = ipv6_header->dst_addr;
		prefix = common::ip_prefix_t(address, 128);
	}

	{
		std::lock_guard<std::mutex> guard(prefixes_mutex);

		if (prefix.is_ipv4())
		{
			for (const auto& local_prefix : local_prefixes_v4)
			{
				if (prefix.get_ipv4().subnetOf(local_prefix))
				{
					return std::nullopt;
				}
			}
		}
		else
		{
			for (const auto& local_prefix : local_prefixes_v6)
			{
				if (prefix.get_ipv6().subnetOf(local_prefix))
				{
					return std::nullopt;
				}
			}
		}

		auto append = [this, &directions, &prefix, &mask_max](const uint32_t& value_id, const uint32_t mask) {
			auto it = values.find(value_id);
			if (it != values.end())
			{
				for (const auto& [nexthop, label, community, peer_as, origin_as, is_best] : it->second)
				{
					directions[{nexthop, label}] = {prefix.applyMask(mask),
					                                nexthop,
					                                is_best,
					                                label,
					                                community,
					                                peer_as,
					                                origin_as};

					mask_max = mask;
				}
			}
		};

		if (dregress.onlyLongest)
		{
			auto dregress_prefixes_value = prefixes.lookup(prefix);
			if (dregress_prefixes_value)
			{
				std::apply(append, *dregress_prefixes_value);
			}
		}
		else
		{
			prefixes.lookup_all(prefix, append);
		}
	}

	if (directions.empty())
	{
		return std::nullopt;
	}

	auto direction = (*std::next(directions.begin(), rand() % directions.size())).second;
	{
		auto& [prefix, nexthop, is_best, label, community, peer_as, origin_as] = direction;
		(void)nexthop;
		(void)label;
		(void)community;
		(void)peer_as;
		(void)origin_as;

		if (prefix.mask() != mask_max)
		{
			is_best = false;
		}
	}

	return direction;
}

bool dregress_t::tcp_parse(rte_mbuf* mbuf,
                           uint16_t& rtt,
                           uint32_t& loss_count,
                           uint32_t& ack_count)
{
	struct tcp_option_t
	{
		uint8_t kind;
		uint8_t len;
	} __attribute__((__packed__));

	struct tcp_option_ya_t
	{
		uint8_t kind;
		uint8_t len;
		uint16_t magic;
		uint16_t rtt;
		uint32_t loss_count;
		uint32_t ack_count;
	} __attribute__((__packed__));

	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	rte_tcp_hdr* tcpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);

	uint16_t tcpDataOffset = (tcpHeader->data_off >> 4) * 4;
	if (tcpDataOffset < sizeof(rte_tcp_hdr) ||
	    metadata->transport_headerOffset + tcpDataOffset > rte_pktmbuf_pkt_len(mbuf))
	{
		/// Invalid data offset, do nothing here
		stats.tcp_no_option++;
		return false;
	}

	uint16_t tcpOptionOffset = sizeof(rte_tcp_hdr);
	while (tcpOptionOffset + sizeof(tcp_option_ya_t) <= tcpDataOffset)
	{
		const uint8_t kind = *rte_pktmbuf_mtod_offset(mbuf, uint8_t*, metadata->transport_headerOffset + tcpOptionOffset);

		if (kind == TCP_OPTION_KIND_EOL ||
		    kind == TCP_OPTION_KIND_NOP)
		{
			tcpOptionOffset++;
			continue;
		}

		const tcp_option_t* option = rte_pktmbuf_mtod_offset(mbuf, tcp_option_t*, metadata->transport_headerOffset + tcpOptionOffset);
		if (option->len == 0)
		{
			stats.tcp_no_option++;
			return false;
		}

		if (kind == TCP_OPTION_KIND_MSS ||
		    kind == TCP_OPTION_KIND_WS ||
		    kind == TCP_OPTION_KIND_SP ||
		    kind == TCP_OPTION_KIND_SACK ||
		    kind == TCP_OPTION_KIND_TS)
		{
			tcpOptionOffset += option->len;
		}
		else if (kind == YANET_TCP_OPTION_YA_KIND)
		{
			const tcp_option_ya_t* option = rte_pktmbuf_mtod_offset(mbuf, tcp_option_ya_t*, metadata->transport_headerOffset + tcpOptionOffset);

			if (option->magic == rte_cpu_to_be_16(YANET_TCP_OPTION_YA_MAGIC))
			{
				rtt = rte_be_to_cpu_16(option->rtt);
				loss_count = rte_be_to_cpu_32(option->loss_count);
				ack_count = rte_be_to_cpu_32(option->ack_count);

				return true;
			}
			else
			{
				tcpOptionOffset += option->len;
			}
		}
		else
		{
			stats.tcp_unknown_option++;
			return false;
		}
	}

	stats.tcp_no_option++;
	return false;
}

common::idp::get_dregress_counters::response dregress_t::get_dregress_counters()
{
	common::idp::get_dregress_counters::response response;

	{
		std::lock_guard<std::mutex> guard(counters_mutex); ///< @todo: free lock
		common::stream_out_t stream;
		counters_v4.push(stream);
		counters_v6.push(stream);
		response = stream.getBuffer();

		YANET_MEMORY_BARRIER_COMPILE;

		counters_v4.clear(); ///< @todo: swap
		counters_v6.clear(); ///< @todo: swap
	}

	return response;
}

void dregress_t::limits(common::idp::limits::response& response)
{
	limit_insert(response,
	             "dregress.ht.keys",
	             connections->getStats().pairs,
	             connections->keysSize);
	limit_insert(response,
	             "dregress.ht.extended_chunks",
	             connections->getStats().extendedChunksCount,
	             YANET_CONFIG_DREGRESS_HT_EXTENDED_SIZE);
}
