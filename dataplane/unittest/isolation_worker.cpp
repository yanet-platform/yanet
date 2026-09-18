#include <gtest/gtest.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>

#include "dataplane/worker.cpp"

namespace
{
class WorkerDataPlane : public cDataPlane
{
public:
	WorkerDataPlane()
	{
		mempool_log = nullptr;
	}
};

class ControlPlaneWorker : public cWorker
{
public:
	ControlPlaneWorker(cDataPlane* dataplane) :
	        cWorker(dataplane)
	{
		std::memset(&stats, 0, sizeof(stats));
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

TEST(ControlPlaneIsolation, OrdinaryWorkerForwardsArpWithoutPacketWarnings)
{
	constexpr unsigned ring_size = 16;
	const auto ring_bytes = rte_ring_get_memsize(ring_size);
	ASSERT_GT(ring_bytes, 0);
	std::unique_ptr<void, decltype(&std::free)> ring_memory(
	        std::aligned_alloc(RTE_CACHE_LINE_SIZE, ring_bytes), &std::free);
	ASSERT_NE(nullptr, ring_memory);
	auto* ring = static_cast<rte_ring*>(ring_memory.get());
	ASSERT_EQ(0, rte_ring_init(ring, "isolation-worker", ring_size, RING_F_SP_ENQ | RING_F_SC_DEQ));

	WorkerDataPlane data_plane;
	auto worker_pointer = std::make_unique<ControlPlaneWorker>(&data_plane);
	auto& worker = *worker_pointer;
	worker.ring_normalPriority = ring;
	alignas(RTE_CACHE_LINE_SIZE) std::array<uint8_t, RTE_PKTMBUF_HEADROOM + sizeof(rte_ether_hdr)> buffer{};
	auto* metadata = new (buffer.data()) dataplane::metadata{};
	metadata->network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
	auto* ethernet = new (buffer.data() + RTE_PKTMBUF_HEADROOM) rte_ether_hdr{};
	std::memset(ethernet->dst_addr.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);
	ethernet->ether_type = metadata->network_headerType;
	rte_mbuf packet{};
	packet.buf_addr = buffer.data();
	packet.data_off = RTE_PKTMBUF_HEADROOM;
	packet.data_len = sizeof(rte_ether_hdr);
	packet.pkt_len = packet.data_len;
	packet.nb_segs = 1;
	rte_mbuf_refcnt_set(&packet, 1);
	worker.controlPlane_stack.insert(&packet);

	testing::internal::CaptureStdout();
	worker.controlPlane_handle();
	const auto output = testing::internal::GetCapturedStdout();

	void* forwarded = nullptr;
	ASSERT_EQ(0, rte_ring_sc_dequeue(ring, &forwarded));
	EXPECT_EQ(&packet, forwarded);
	EXPECT_EQ(1u, worker.stats.interface_isolated_cp_miss);
	EXPECT_EQ(1u, worker.stats.ring_normalPriority_packets);
	EXPECT_EQ(0u, worker.stats.ring_normalPriority_drops);
	EXPECT_EQ(0u, worker.controlPlane_stack.mbufsCount);
	EXPECT_TRUE(output.empty()) << output;
}
}
