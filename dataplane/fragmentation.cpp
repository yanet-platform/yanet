#include "fragmentation.h"
#include "common.h"
#include "metadata.h"

namespace fragmentation
{

Fragmentation::Fragmentation(OnCollected callback) :
        callback_{std::move(callback)}
{}

Fragmentation::Fragmentation(OnCollected callback, const FragmentationConfig& cfg) :
        callback_{std::move(callback)},
        config_{cfg}
{
	memset(&stats_, 0, sizeof(stats_));
}

Fragmentation::Fragmentation(Fragmentation&& other)
{
	*this = std::move(other);
}

Fragmentation::~Fragmentation()
{
	for (const auto& [key, value] : fragments_)
	{
		GCC_BUG_UNUSED(key);

		for (const auto& [range_from, range_value] : std::get<0>(value))
		{
			GCC_BUG_UNUSED(range_from);

			const auto& [range_to, mbuf] = range_value;
			GCC_BUG_UNUSED(range_to);

			rte_pktmbuf_free(mbuf);
		}
	}
}

common::fragmentation::stats_t Fragmentation::getStats() const
{
	return stats_;
}

void Fragmentation::insert(rte_mbuf* mbuf)
{
	if (stats_.current_count_packets > config_.size)
	{
		YANET_LOG_DEBUG("Frag limit exceeded\n");
		stats_.total_overflow_packets++;
		rte_pktmbuf_free(mbuf);
		return;
	}

	uint16_t currentTime = time(nullptr);

	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	if (!(metadata->network_flags & YANET_NETWORK_FLAG_FRAGMENT))
	{
		stats_.not_fragment_packets++;
		rte_pktmbuf_free(mbuf);
		return;
	}

	uint32_t range_from = 0;
	uint32_t range_to = 0;
	fragmentation::key_t key;

	if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
	{
		rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);

		/// ipv4Header->total_length checked in cWorker::preparePacket()
		range_from = (rte_be_to_cpu_16(ipv4Header->fragment_offset) & 0x1FFF) * 8;
		range_to = range_from + rte_be_to_cpu_16(ipv4Header->total_length) - (metadata->transport_headerOffset - metadata->network_headerOffset);

		if (range_from == range_to)
		{
			stats_.empty_packets++;
			rte_pktmbuf_free(mbuf);
			return;
		}

		if (rte_be_to_cpu_16(ipv4Header->fragment_offset) & 0x2000)
		{
			range_to--;
		}
		else
		{
			range_to = 0xFFFFFFFF;
		}

		key = fragmentation::key_ipv4_t{metadata->flow.type, ///< @todo
		                                metadata->flow.getId(), ///< @todo
		                                {ipv4Header->src_addr},
		                                {ipv4Header->dst_addr},
		                                ipv4Header->packet_id};
	}
	else if (metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
	{
		rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
		ipv6_extension_fragment_t* extension = rte_pktmbuf_mtod_offset(mbuf, ipv6_extension_fragment_t*, metadata->network_fragmentHeaderOffset);

		/// ipv6Header->payload_len checked in cWorker::preparePacket()
		range_from = (rte_be_to_cpu_16(extension->offsetFlagM) >> 3) * 8;
		range_to = range_from + rte_be_to_cpu_16(ipv6Header->payload_len) - (metadata->transport_headerOffset - metadata->network_headerOffset) + sizeof(rte_ipv6_hdr);

		if (range_from == range_to)
		{
			stats_.empty_packets++;
			rte_pktmbuf_free(mbuf);
			return;
		}

		if (rte_be_to_cpu_16(extension->offsetFlagM) & 0x0001)
		{
			range_to--;
		}
		else
		{
			range_to = 0xFFFFFFFF;
		}

		key = fragmentation::key_ipv6_t{metadata->flow.type, ///< @todo
		                                metadata->flow.getId(), ///< @todo
		                                {ipv6Header->src_addr},
		                                {ipv6Header->dst_addr},
		                                extension->identification};
	}
	else
	{
		stats_.unknown_network_type_packets++;
		rte_pktmbuf_free(mbuf);
		return;
	}

	if (!exist(fragments_, key))
	{
		fragments_[key] = {{{range_from,
		                     {range_to,
		                      mbuf}}},
		                   currentTime,
		                   currentTime};
	}
	else
	{
		auto& value = fragments_[key];

		if (std::get<0>(value).size() > config_.packets_per_flow)
		{
			stats_.flow_overflow_packets++;
			rte_pktmbuf_free(mbuf);
			return;
		}

		if (isIntersect(value, range_from, range_to))
		{
			stats_.intersect_packets++;
			rte_pktmbuf_free(mbuf);
			return;
		}

		std::get<0>(value)[range_from] = {range_to, mbuf};
		std::get<2>(value) = currentTime;
	}

	stats_.current_count_packets++;
}

void Fragmentation::handle()
{
	std::vector<fragmentation::key_t> gc_keys;

	for (auto& [key, value] : fragments_)
	{
		if (isTimeout(value))
		{
			gc_keys.emplace_back(key);
			continue;
		}

		if (isCollected(value))
		{
			rte_mbuf* lastPacket_mbuf = std::get<1>(std::get<0>(value).rbegin()->second);

			dataplane::metadata* firstPacket_metadata = YADECAP_METADATA(std::get<1>(std::get<0>(value).begin()->second));
			dataplane::metadata* lastPacket_metadata = YADECAP_METADATA(lastPacket_mbuf);

			const uint16_t& lastPacket_range_from = std::get<0>(value).rbegin()->first;

			if (firstPacket_metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			{
				rte_ipv4_hdr* ipv4Header = rte_pktmbuf_mtod_offset(lastPacket_mbuf, rte_ipv4_hdr*, lastPacket_metadata->network_headerOffset);

				firstPacket_metadata->payload_length = lastPacket_range_from +
				                                       rte_be_to_cpu_16(ipv4Header->total_length) -
				                                       (lastPacket_metadata->transport_headerOffset - lastPacket_metadata->network_headerOffset);
			}
			else if (firstPacket_metadata->network_headerType == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
			{
				rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(lastPacket_mbuf, rte_ipv6_hdr*, lastPacket_metadata->network_headerOffset);

				firstPacket_metadata->payload_length = lastPacket_range_from +
				                                       rte_be_to_cpu_16(ipv6Header->payload_len) -
				                                       (lastPacket_metadata->transport_headerOffset - lastPacket_metadata->network_headerOffset) +
				                                       sizeof(rte_ipv6_hdr);
			}
			else
			{
				/// you found a secret area

				gc_keys.emplace_back(key);
				continue;
			}

			for (auto& [range_from, range_value] : std::get<0>(value))
			{
				GCC_BUG_UNUSED(range_from);

				const auto& [range_to, mbuf] = range_value;
				GCC_BUG_UNUSED(range_to);

				dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
				metadata->flow.data = firstPacket_metadata->flow.data;

				callback_(mbuf, metadata->flow);
				stats_.current_count_packets--;
			}

			std::get<0>(value).clear();
			gc_keys.emplace_back(key);
		}
	}

	for (const auto& key : gc_keys)
	{
		for (auto& [range_from, range_value] : std::get<0>(fragments_[key]))
		{
			GCC_BUG_UNUSED(range_from);

			const auto& [range_to, mbuf] = range_value;
			GCC_BUG_UNUSED(range_to);

			stats_.timeout_packets++;
			rte_pktmbuf_free(mbuf);

			stats_.current_count_packets--;
		}

		fragments_.erase(key);
	}
}

bool Fragmentation::isTimeout(const fragmentation::value_t& value) const
{
	uint16_t currentTime = time(nullptr);

	if ((uint16_t)(currentTime - std::get<1>(value)) >= config_.timeout_first)
	{
		return true;
	}

	if ((uint16_t)(currentTime - std::get<2>(value)) >= config_.timeout_last)
	{
		return true;
	}

	return false;
}

bool Fragmentation::isCollected(const fragmentation::value_t& value) const
{
	uint32_t next_range_from = 0;
	for (const auto& [range_from, range_value] : std::get<0>(value))
	{
		const auto& [range_to, mbuf] = range_value;
		GCC_BUG_UNUSED(mbuf);

		if (range_from != next_range_from)
		{
			return false;
		}

		if (range_to == 0xFFFFFFFF)
		{
			return true;
		}

		next_range_from = range_to + 1;
	}

	return false;
}

bool Fragmentation::isIntersect(const fragmentation::value_t& value,
                                const uint32_t& second_range_from,
                                const uint32_t& second_range_to) const
{
	for (const auto& [range_from, range_value] : std::get<0>(value))
	{
		const auto& [range_to, mbuf] = range_value;
		GCC_BUG_UNUSED(mbuf);

		if (second_range_to < range_from)
		{
			continue;
		}
		else if (second_range_from > range_to)
		{
			continue;
		}

		return true;
	}

	return false;
}
} // namespace fragmentation