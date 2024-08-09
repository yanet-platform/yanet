#pragma once
#include <queue>
#include <tuple>
#include <vector>

#include "dpdk.h"
#include "dregress.h"
#include "fragmentation.h"
#include "kernel_interface_handler.h"
#include "worker.h"

namespace dataplane
{

class SlowWorker
{
public:
	struct Config
	{
		uint32_t SWICMPOutRateLimit = 0;
		bool use_kernel_interface;
	};

private:
	std::vector<tPortId> ports_serviced_;
	std::vector<cWorker*> workers_serviced_;
	std::vector<dpdk::RingConn<rte_mbuf*>> from_gcs_;
	cWorker* slow_worker_;
	std::queue<std::tuple<rte_mbuf*, common::globalBase::tFlow>> slow_worker_mbufs_;
	rte_mempool* mempool_; // from cControlPlane
	common::slowworker::stats_t stats_;
	fragmentation::Fragmentation fragmentation_;
	dregress_t dregress_;
	uint32_t icmp_out_remainder_;
	Config config_;
	dataplane::KernelInterfaceWorker kni_worker_;

	auto SlowWorkerSender()
	{
		return [this](rte_mbuf* pkt, const common::globalBase::tFlow& flow) {
			SendToSlowWorker(pkt, flow);
		};
	}
	using VipToBalancers = std::vector<std::unordered_map<common::ip_address_t, std::unordered_set<common::ip_address_t>>>;
	using VipVportProto = std::vector<std::unordered_set<std::tuple<common::ip_address_t, std::optional<uint16_t>, uint8_t>>>;
	void BalancerICMPForwardCriticalSection(
	        rte_mbuf* mbuf,
	        VipToBalancers& vip_to_balancers,
	        VipVportProto& vip_vport_proto);

public:
	SlowWorker(cWorker* worker,
	           std::vector<tPortId>&& ports_to_service,
	           std::vector<cWorker*>&& workers_to_service,
	           std::vector<dpdk::RingConn<rte_mbuf*>>&& from_gcs,
	           KernelInterfaceWorker&& kni,
	           rte_mempool* mempool,
	           bool use_kni,
	           uint32_t sw_icmp_out_rate_limit);
	SlowWorker(const SlowWorker&) = delete;
	SlowWorker(SlowWorker&& other);
	SlowWorker& operator=(const SlowWorker&) = delete;
	SlowWorker& operator=(SlowWorker&& other);

	cWorker* GetWorker() { return slow_worker_; }
	const dataplane::KernelInterfaceWorker& KniWorker() const { return kni_worker_; }
	const dataplane::base::generation& current_base() { return slow_worker_->current_base(); }
	const fragmentation::Fragmentation& Fragmentation() const { return fragmentation_; }
	dregress_t& Dregress() { return dregress_; }
	const dregress_t& Dregress() const { return dregress_; }
	void freeWorkerPacket(rte_ring* ring_to_free_mbuf, rte_mbuf* mbuf);
	rte_mbuf* convertMempool(rte_ring* ring_to_free_mbuf, rte_mbuf* old_mbuf);
	rte_mempool* Mempool() { return mempool_; }
	void PreparePacket(rte_mbuf* mbuf) { slow_worker_->preparePacket(mbuf); }
	void SendToSlowWorker(rte_mbuf* mbuf, const common::globalBase::tFlow& flow);
	void ResetIcmpOutRemainder(uint32_t limit) { icmp_out_remainder_ = limit; }

	const common::slowworker::stats_t& Stats() const { return stats_; }
	unsigned ring_handle(rte_ring* ring_to_free_mbuf, rte_ring* ring);
	void handlePacket_icmp_translate_v6_to_v4(rte_mbuf* mbuf);
	void handlePacket_icmp_translate_v4_to_v6(rte_mbuf* mbuf);
	void handlePacket_fragment(rte_mbuf* mbuf);
	void handlePacket_dregress(rte_mbuf* mbuf);
	void handlePacket_farm(rte_mbuf* mbuf);
	void handlePacket_repeat(rte_mbuf* mbuf);
	void handlePacket_fw_state_sync(rte_mbuf* mbuf);
	bool handlePacket_fw_state_sync_ingress(rte_mbuf* mbuf);
	void handlePacket_balancer_icmp_forward(rte_mbuf* mbuf);
	void handlePacketFromForwardingPlane(rte_mbuf* mbuf);
	void HandleWorkerRings();

	// \brief dequeue packets from worker_gc's ring to slowworker
	void DequeueGC();

	void Iteration()
	{
		slow_worker_->slowWorkerBeforeHandlePackets();

		HandleWorkerRings();

		if (config_.use_kernel_interface)
		{
			kni_worker_.Flush();
		}

		DequeueGC();
		fragmentation_.handle();
		dregress_.handle();

		if (config_.use_kernel_interface)
		{
			kni_worker_.ForwardToPhy();
			kni_worker_.RecvFree();
		}

		/// push packets to slow worker
		while (!slow_worker_mbufs_.empty())
		{
			for (unsigned int i = 0;
			     i < CONFIG_YADECAP_MBUFS_BURST_SIZE;
			     i++)
			{
				if (slow_worker_mbufs_.empty())
				{
					break;
				}

				auto& tuple = slow_worker_mbufs_.front();
				slow_worker_->slowWorkerFlow(std::get<0>(tuple), std::get<1>(tuple));

				slow_worker_mbufs_.pop();
			}

			slow_worker_->slowWorkerHandlePackets();
		}

		slow_worker_->slowWorkerAfterHandlePackets();
#ifdef CONFIG_YADECAP_AUTOTEST
		std::this_thread::sleep_for(std::chrono::microseconds{1});
#endif // CONFIG_YADECAP_AUTOTEST
	}
};

} // namespace dataplane
