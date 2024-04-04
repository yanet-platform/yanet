#pragma once

#include <array>
#include <cstdint>

#include <rte_ethdev.h>
#include <rte_mbuf.h>

namespace dpdk
{

template<std::uint16_t BSize>
class BasicBurst
{
	std::array<rte_mbuf*, BSize> m_burst;
	std::uint16_t m_begin = 0;
	std::uint16_t m_end = 0;

public:
	BasicBurst() = default;
	BasicBurst(const BasicBurst& other) = delete;
	BasicBurst(BasicBurst&& other) = default;
	~BasicBurst()
	{
		Free();
	};
	BasicBurst& operator=(const BasicBurst& other) = delete;
	BasicBurst& operator=(BasicBurst&& other) = default;
	rte_mbuf** begin()
	{
		return m_burst.data() + m_begin;
	}
	rte_mbuf** end()
	{
		return m_burst.data() + m_end;
	}
	[[nodiscard]] rte_mbuf* Pop()
	{
		return m_burst[m_begin++];
	}
	[[nodiscard]] bool Push(rte_mbuf* m)
	{
		bool can_push = m_end < m_burst.size();
		if (can_push)
		{
			PushUnsafe(m);
		}
		return can_push;
	}
	void PushUnsafe(rte_mbuf* m)
	{
		m_burst[m_end++] = m;
	}
	BasicBurst& Rx(uint16_t port_id, uint16_t queue_id)
	{
		if (!empty())
			Free();
		m_begin = 0;
		m_end = rte_eth_rx_burst(port_id, queue_id, m_burst.data(), m_burst.size());
		return *this;
	}
	BasicBurst& Tx(uint16_t port_id, uint16_t queue_id)
	{
		m_begin += rte_eth_tx_burst(port_id, queue_id, begin(), Packets());
		return *this;
	}
	struct TxStats
	{
		uint64_t opackets = 0;
		uint64_t obytes = 0;
	};
	TxStats TxTracked(tPortId port_id, tQueueId queue_id)
	{
		if (empty())
			return TxStats{};
		TxStats stats{0, Bytes()};

		stats.opackets = rte_eth_tx_burst(port_id, queue_id, begin(), Packets());
		m_begin += stats.opackets;

		stats.obytes -= Bytes();

		return stats;
	}
	uint16_t Packets() { return m_end - m_begin; }
	uint64_t Bytes()
	{
		return std::accumulate(begin(), end(), 0, [](uint64_t total, rte_mbuf* mbuf) {
			return total + rte_pktmbuf_pkt_len(mbuf);
		});
	}
	uint16_t Free()
	{
		uint16_t count = Packets();
		rte_pktmbuf_free_bulk(m_burst.data() + m_begin, count);
		m_begin = 0;
		m_end = 0;
		return count;
	}
	[[nodiscard]] bool empty()
	{
		return m_begin == m_end;
	}
};

using Burst = BasicBurst<CONFIG_YADECAP_MBUFS_BURST_SIZE>;

} // namespace dpdk
