#include <gtest/gtest.h>

#include <array>
#include <cstdlib>
#include <memory>
#include <new>

#include "dataplane/worker.cpp"

namespace
{
class ControlPlaneWorker : public cWorker
{
public:
	ControlPlaneWorker(cDataPlane* dataplane) :
	        cWorker(dataplane)
	{
		stats = {};
	}

	~ControlPlaneWorker()
	{
		ring_normalPriority = nullptr;
	}

	using cWorker::controlPlane_handle;
	using cWorker::controlPlane_stack;
	using cWorker::ring_normalPriority;
	using cWorker::stats;
};

TEST(ControlPlaneIsolation, CountsOnlyReceivedPacketsWithoutPacketWarnings)
{
	constexpr unsigned ring_size = 16;
	const auto ring_bytes = rte_ring_get_memsize(ring_size);
	ASSERT_GT(ring_bytes, 0);
	std::unique_ptr<void, decltype(&std::free)> ring_memory(
	        std::aligned_alloc(RTE_CACHE_LINE_SIZE, ring_bytes), &std::free);
	ASSERT_NE(nullptr, ring_memory);
	auto* ring = static_cast<rte_ring*>(ring_memory.get());
	ASSERT_EQ(0, rte_ring_init(ring, "isolation-worker", ring_size, RING_F_SP_ENQ | RING_F_SC_DEQ));

	struct Packet
	{
		alignas(RTE_CACHE_LINE_SIZE) std::array<uint8_t, RTE_PKTMBUF_HEADROOM + sizeof(rte_ether_hdr)> buffer{};
		rte_mbuf mbuf{};
	};
	std::array<Packet, 4> packets{};
	size_t packet_index = 0;
	for (const auto flow_type : {common::globalBase::eFlowType::slowWorker_kni, common::globalBase::eFlowType::slowWorker_fw_sync})
	{
		for (const auto destination : {rte_ether_addr{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		                               rte_ether_addr{{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}}})
		{
			auto& packet = packets[packet_index++];
			auto* metadata = new (packet.buffer.data()) dataplane::metadata{};
			metadata->flow.type = flow_type;
			metadata->network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
			auto* ethernet = new (packet.buffer.data() + RTE_PKTMBUF_HEADROOM) rte_ether_hdr{};
			ethernet->dst_addr = destination;
			ethernet->ether_type = metadata->network_headerType;
			packet.mbuf.buf_addr = packet.buffer.data();
			packet.mbuf.data_off = RTE_PKTMBUF_HEADROOM;
			packet.mbuf.data_len = sizeof(rte_ether_hdr);
			packet.mbuf.pkt_len = packet.mbuf.data_len;
			packet.mbuf.nb_segs = 1;
			rte_mbuf_refcnt_set(&packet.mbuf, 1);
		}
	}

	cDataPlane data_plane;
	for (const bool isolated_worker : {false, true})
	{
		SCOPED_TRACE(isolated_worker);
		auto worker_pointer = std::make_unique<ControlPlaneWorker>(&data_plane);
		auto& worker = *worker_pointer;
		worker.ring_normalPriority = ring;
		if (isolated_worker)
		{
			worker.SetWorkerAsIsolatedCP();
		}
		for (auto& packet : packets)
		{
			worker.controlPlane_stack.insert(&packet.mbuf);
		}

		testing::internal::CaptureStdout();
		worker.controlPlane_handle();
		const auto output = testing::internal::GetCapturedStdout();

		for (auto& packet : packets)
		{
			void* forwarded = nullptr;
			ASSERT_EQ(0, rte_ring_sc_dequeue(ring, &forwarded));
			EXPECT_EQ(&packet.mbuf, forwarded);
		}
		EXPECT_EQ(isolated_worker ? 2u : 0u, worker.stats.interface_isolated_cp);
		EXPECT_EQ(isolated_worker ? 0u : 1u, worker.stats.interface_isolated_cp_miss);
		EXPECT_EQ(isolated_worker ? 0u : 1u, worker.stats.interface_isolated_cp_fixed_mac);
		EXPECT_EQ(4u, worker.stats.ring_normalPriority_packets);
		EXPECT_EQ(0u, worker.stats.ring_normalPriority_drops);
		EXPECT_EQ(0u, worker.controlPlane_stack.mbufsCount);
		EXPECT_TRUE(output.empty()) << output;
	}
}
}
