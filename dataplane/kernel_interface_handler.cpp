#include "kernel_interface_handler.h"
#include "metadata.h"

namespace dataplane
{
KernelInterface::KernelInterface(tPortId port, tQueueId queue) :
        endpoint_{port, queue}
{
}

KernelInterface::KernelInterface(const dpdk::Endpoint& e) :
        endpoint_{e}
{
}

void KernelInterface::Flush()
{
	auto sent = rte_eth_tx_burst(endpoint_.port, endpoint_.queue, burst_, burst_length_);
	const auto remain = burst_length_ - sent;
	if (remain)
	{
		rte_pktmbuf_free_bulk(burst_ + sent, remain);
	}
	burst_length_ = 0;
}

KernelInterface::DirectionStats KernelInterface::FlushTracked()
{
	DirectionStats stats;
	stats.bytes = std::accumulate(burst_, burst_ + burst_length_, 0, [](uint64_t total, rte_mbuf* mbuf) {
		return total + rte_pktmbuf_pkt_len(mbuf);
	});
	stats.packets = rte_eth_tx_burst(endpoint_.port, endpoint_.queue, burst_, burst_length_);

	stats.dropped = burst_length_ - stats.packets;
	if (stats.dropped)
	{
		stats.bytes = std::accumulate(burst_ + stats.packets, burst_ + burst_length_, stats.bytes, [](uint64_t total, rte_mbuf* mbuf) {
			return total - rte_pktmbuf_pkt_len(mbuf);
		});
		rte_pktmbuf_free_bulk(burst_ + stats.packets, stats.dropped);
	}
	burst_length_ = 0;

	return stats;
}

void KernelInterface::Push(rte_mbuf* mbuf)
{
	if (burst_length_ == YANET_CONFIG_BURST_SIZE)
	{
		Flush();
	}
	burst_[burst_length_++] = mbuf;
}

KernelInterface::DirectionStats KernelInterface::PushTracked(rte_mbuf* mbuf)
{
	DirectionStats res;
	if (burst_length_ == YANET_CONFIG_BURST_SIZE)
	{
		res = FlushTracked();
	}
	burst_[burst_length_++] = mbuf;
	return res;
}

const tPortId& KernelInterface::port() const
{
	return endpoint_.port;
}

const tQueueId& KernelInterface::queue() const
{
	return endpoint_.queue;
}

void KernelInterfaceWorker::RecvFree(const KernelInterface& iface)
{
	rte_mbuf* burst[CONFIG_YADECAP_MBUFS_BURST_SIZE];
	auto len = rte_eth_rx_burst(iface.port(), iface.queue(), burst, CONFIG_YADECAP_MBUFS_BURST_SIZE);
	rte_pktmbuf_free_bulk(burst, len);
}

KernelInterfaceWorker::KernelInterfaceWorker(std::vector<KernelInterfaceBundleConfig>& interfaces)
{
	for (const auto& iface : interfaces)
	{
		auto mapped = port_mapper_.Register(iface.phy.port);
		if (!mapped || mapped != size_)
		{
			YANET_LOG_ERROR("Failed to register port with kernel interface worker (%d)\n", iface.phy.port);
			abort();
		}
		phy_ports_[size_] = iface.phy.port;
		phy_queues_[size_] = iface.phy.queue;
		forward_[size_] = KernelInterface{iface.forward};
		in_dump_[size_] = KernelInterface{iface.in_dump};
		out_dump_[size_] = KernelInterface{iface.out_dump};
		drop_dump_[size_] = KernelInterface{iface.drop_dump};
		++size_;
	}
}

KernelInterfaceWorker::KernelInterfaceWorker(KernelInterfaceWorker&& other)
{
	*this = std::move(other);
}

KernelInterfaceWorker& KernelInterfaceWorker::operator=(KernelInterfaceWorker&& other)
{
	size_ = std::exchange(other.size_, 0);
	for (std::size_t i = 0; i < size_; ++i)
	{
		phy_ports_[i] = other.phy_ports_[i];
		phy_queues_[i] = other.phy_queues_[i];
		forward_[i] = other.forward_[i];
		in_dump_[i] = other.in_dump_[i];
		out_dump_[i] = other.out_dump_[i];
		drop_dump_[i] = other.drop_dump_[i];
	}
	port_mapper_ = std::move(other.port_mapper_);
	return *this;
}

KernelInterfaceWorker::ConstPortArrayRange<tPortId>
KernelInterfaceWorker::PortsIds() const
{
	return {phy_ports_.begin(), phy_ports_.begin() + size_};
}

KernelInterfaceWorker::ConstPortArrayRange<sKniStats>
KernelInterfaceWorker::PortsStats() const
{
	return {stats_.begin(), stats_.begin() + size_};
}

std::optional<std::reference_wrapper<const sKniStats>>
KernelInterfaceWorker::PortStats(tPortId pid) const
{
	for (std::size_t i = 0; i < size_; ++i)
	{
		if (phy_ports_[i] == pid)
		{
			return stats_[i];
		}
	}
	return std::nullopt;
}

/// @brief Transmit accumulated packets. Those that could not be sent are freed
void KernelInterfaceWorker::Flush()
{
	for (std::size_t i = 0; i < size_; ++i)
	{
		const auto& delta = forward_[i].FlushTracked();
		stats_[i].opackets += delta.packets;
		stats_[i].obytes += delta.bytes;
		stats_[i].odropped += delta.dropped;
		in_dump_[i].Flush();
		out_dump_[i].Flush();
		drop_dump_[i].Flush();
	}
}

/// @brief Receive from in.X/out.X/drop.X interfaces and free packets
void KernelInterfaceWorker::RecvFree()
{
	for (std::size_t i = 0; i < size_; ++i)
	{
		RecvFree(in_dump_[i]);
		RecvFree(out_dump_[i]);
		RecvFree(drop_dump_[i]);
	}
}

/// @brief Receive packets from kernel interface and send to physical port
void KernelInterfaceWorker::ForwardToPhy()
{
	for (std::size_t i = 0; i < size_; ++i)
	{
		rte_mbuf* burst[CONFIG_YADECAP_MBUFS_BURST_SIZE];
		auto packets = rte_eth_rx_burst(forward_[i].port(), forward_[i].queue(), burst, CONFIG_YADECAP_MBUFS_BURST_SIZE);
		uint64_t bytes = std::accumulate(burst, burst + packets, 0, [](uint64_t total, rte_mbuf* mbuf) {
			return total + rte_pktmbuf_pkt_len(mbuf);
		});
		auto transmitted = rte_eth_tx_burst(phy_ports_[i], phy_queues_[i], burst, packets);
		const auto remain = packets - transmitted;

		if (remain)
		{
			bytes = std::accumulate(burst, burst + packets, bytes, [](uint64_t total, rte_mbuf* mbuf) {
				return total - rte_pktmbuf_pkt_len(mbuf);
			});
			rte_pktmbuf_free_bulk(burst + transmitted, remain);
		}

		auto& stats = stats_[i];
		stats.ipackets += transmitted;
		stats.ibytes += bytes;
		stats.idropped += remain;
	}
}

void KernelInterfaceWorker::HandlePacketDump(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	if (!port_mapper_.ValidDpdk(metadata->flow.data.dump.id))
	{
		unknown_dump_interface_++;
		rte_pktmbuf_free(mbuf);
		return;
	}
	const auto local_port_id = port_mapper_.ToLogical(metadata->flow.data.dump.id);

	using dumpType = common::globalBase::dump_type_e;
	switch (metadata->flow.data.dump.type)
	{
		case dumpType::physicalPort_ingress:
			in_dump_[local_port_id].Push(mbuf);
			break;
		case dumpType::physicalPort_egress:
			out_dump_[local_port_id].Push(mbuf);
			break;
		case dumpType::physicalPort_drop:
			drop_dump_[local_port_id].Push(mbuf);
			break;
		default:
			unknown_dump_interface_++;
			rte_pktmbuf_free(mbuf);
	}
}

void KernelInterfaceWorker::HandlePacketFromForwardingPlane(rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	if (!port_mapper_.ValidDpdk(metadata->fromPortId))
	{
		if (unknown_forward_interface_ < 100 || unknown_forward_interface_ % 100 == 0)
		{
			YANET_LOG_ERROR("Failed to map dpdk port %d while handling packet from forwarding plane (occurance %ld)\n", metadata->fromPortId, unknown_forward_interface_);
		}
		++unknown_forward_interface_;
		rte_pktmbuf_free(mbuf);
		return;
	}
	const auto i = port_mapper_.ToLogical(metadata->fromPortId);
	const auto& delta = forward_[i].PushTracked(mbuf);
	stats_[i].opackets += delta.packets;
	stats_[i].obytes += delta.bytes;
	stats_[i].odropped += delta.dropped;
}

} // namespace dataplane
