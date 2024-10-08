#pragma once
#include <vector>

#include <rte_ethdev.h>

#include "base.h"
#include "dpdk.h"
#include "metadata.h"

namespace dataplane
{

struct sKniStats
{
	uint64_t ipackets = 0;
	uint64_t ibytes = 0;
	uint64_t idropped = 0;
	uint64_t opackets = 0;
	uint64_t obytes = 0;
	uint64_t odropped = 0;
};

class KernelInterface
{
	dpdk::Endpoint endpoint_;
	rte_mbuf* burst_[CONFIG_YADECAP_MBUFS_BURST_SIZE];
	uint16_t burst_length_ = 0;

public:
	KernelInterface() = default;
	KernelInterface(tPortId port, tQueueId queue);
	KernelInterface(const dpdk::Endpoint& e);
	struct DirectionStats
	{
		uint64_t bytes = 0;
		uint64_t packets = 0;
		uint64_t dropped = 0;
	};
	void Flush();
	DirectionStats FlushTracked();
	void Push(rte_mbuf* mbuf);
	DirectionStats PushTracked(rte_mbuf* mbuf);
	const tPortId& port() const;
	const tQueueId& queue() const;
};

struct KernelInterfaceBundleConfig
{
	dpdk::Endpoint phy;
	dpdk::Endpoint forward;
	dpdk::Endpoint in_dump;
	dpdk::Endpoint out_dump;
	dpdk::Endpoint drop_dump;
};

class KernelInterfaceWorker
{
public:
	template<typename T>
	using PortArray = std::array<T, CONFIG_YADECAP_PORTS_SIZE>;
	template<typename T>
	using ConstPortArrayRange = std::pair<typename PortArray<T>::const_iterator, typename PortArray<T>::const_iterator>;

private:
	std::size_t size_ = 0;
	PortArray<tPortId> phy_ports_;
	PortArray<tQueueId> phy_queues_;
	PortArray<sKniStats> stats_;
	PortArray<KernelInterface> forward_;
	PortArray<KernelInterface> in_dump_;
	PortArray<KernelInterface> out_dump_;
	PortArray<KernelInterface> drop_dump_;
	dataplane::base::PortMapper port_mapper_;
	uint64_t unknown_dump_interface_ = 0;
	uint64_t unknown_forward_interface_ = 0;

	/**
	 * @brief Receive packets from interface and free them.
	 * @param iface Interface to receive packets from.
	 */
	void RecvFree(const KernelInterface& iface);

public:
	KernelInterfaceWorker(std::vector<KernelInterfaceBundleConfig>& config);
	KernelInterfaceWorker(KernelInterfaceWorker&& other);
	KernelInterfaceWorker& operator=(KernelInterfaceWorker&& other);
	ConstPortArrayRange<tPortId> PortsIds() const;
	ConstPortArrayRange<sKniStats> PortsStats() const;
	std::optional<std::reference_wrapper<const sKniStats>> PortStats(tPortId pid) const;

	/// @brief Transmit accumulated packets. Those that could not be sent are freed
	void Flush();
	/// @brief Receive from in.X/out.X/drop.X interfaces and free packets
	void RecvFree();
	/// @brief Receive packets from kernel interface and send to physical port
	void ForwardToPhy();
	void HandlePacketDump(rte_mbuf* mbuf);
	void HandlePacketFromForwardingPlane(rte_mbuf* mbuf);
};
} // namespace dataplane