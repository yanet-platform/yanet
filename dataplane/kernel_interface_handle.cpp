#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <rte_ethdev.h>

#include "common.h"
#include "kernel_interface_handle.h"
namespace dataplane
{

bool KernelInterfaceHandle::SetUp() const noexcept
{
	int socket = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (socket < 0)
	{
		return false;
	}

	struct ifreq request;
	memset(&request, 0, sizeof request);

	strncpy(request.ifr_name, name_.data(), IFNAMSIZ);

	request.ifr_flags |= IFF_UP;
	if (auto res = ioctl(socket, SIOCSIFFLAGS, &request))
	{
		YANET_LOG_ERROR("failed to set interface %s up, ioctl returned (%d)", name_.data(), res);
		return false;
	}
	return true;
}

KernelInterfaceHandle::~KernelInterfaceHandle()
{
	if (Valid())
		Remove();
}

KernelInterfaceHandle::KernelInterfaceHandle(KernelInterfaceHandle&& other) noexcept
{
	*this = std::move(other);
}

bool KernelInterfaceHandle::Start() const
{
	auto rc = rte_eth_dev_start(kni_port_);
	if (rc)
	{
		YADECAP_LOG_ERROR("can't start eth dev(%d, %d): %s\n",
		                  rc,
		                  rte_errno,
		                  rte_strerror(rte_errno));
		return false;
	}
	return true;
}

KernelInterfaceHandle& KernelInterfaceHandle::operator=(KernelInterfaceHandle&& other) noexcept
{
	if (this != &other)
	{
		std::swap(kni_port_, other.kni_port_);
		std::swap(name_, other.name_);
		std::swap(vdev_name_, other.vdev_name_);
		std::swap(queue_size_, other.queue_size_);
	}
	return *this;
}

std::optional<KernelInterfaceHandle>
KernelInterfaceHandle::MakeKernelInterfaceHandle(
        std::string_view name,
        tPortId port,
        tQueueId queue_count,
        uint16_t queue_size) noexcept
{
	KernelInterfaceHandle kni;
	kni.queue_size_ = queue_size;
	kni.name_ = name;
	kni.vdev_name_ = VdevName(name, port);
	std::string vdev_args = VdevArgs(name, port, queue_count, queue_size);
	if (!kni.Add(kni.vdev_name_, vdev_args) ||
	    !kni.Configure(DefaultConfig(), queue_count))
	{
		return std::nullopt;
	}
	return std::optional<KernelInterfaceHandle>{std::move(kni)};
}

std::string KernelInterfaceHandle::VdevName(std::string_view name, tPortId port_id)
{
	std::stringstream ss;
	ss << "virtio_user_" << name << "_" << port_id;
	return ss.str();
}

std::string KernelInterfaceHandle::VdevArgs(std::string_view name, tPortId port_id, tQueueId queues, uint64_t queue_size)
{
	rte_ether_addr ether_addr;
	rte_eth_macaddr_get(port_id, &ether_addr);
	std::stringstream ss;
	ss << "path=/dev/vhost-net"
	   << ",queues=" << static_cast<int>(queues)
	   << ",queue_size=" << queue_size
	   << ",iface=" << name
	   << ",mac=" << common::mac_address_t(ether_addr.addr_bytes).toString();
	return ss.str();
}

bool KernelInterfaceHandle::Add(const std::string& vdev_name, const std::string& args) noexcept
{
	if (rte_eal_hotplug_add("vdev", vdev_name.data(), args.data()) != 0)
	{
		YADECAP_LOG_ERROR("failed to hotplug vdev interface '%s' with '%s'\n",
		                  vdev_name.data(),
		                  args.data());
		return false;
	}

	if (rte_eth_dev_get_port_by_name(vdev_name.data(), &kni_port_) != 0)
	{
		YADECAP_LOG_ERROR("vdev interface '%s' not found\n", vdev_name.data());
		return false;
	}
	YANET_LOG_INFO("vdev '%s' with portId %d (%s)\n", vdev_name.data(), kni_port_, args.data());
	return true;
}

void KernelInterfaceHandle::Remove() noexcept
{
	rte_eal_hotplug_remove("vdev", vdev_name_.data());
	MarkInvalid();
}

rte_eth_conf KernelInterfaceHandle::DefaultConfig() noexcept
{
	return rte_eth_conf{};
}

bool KernelInterfaceHandle::Configure(const rte_eth_conf& eth_conf, tQueueId queue_count)
{
	int ret = rte_eth_dev_configure(kni_port_,
	                                queue_count,
	                                queue_count,
	                                &eth_conf);
	if (ret < 0)
	{
		YADECAP_LOG_ERROR("rte_eth_dev_configure() = %d\n", ret);
		return false;
	}
	return true;
}

bool KernelInterfaceHandle::CloneMTU(const uint16_t port_id) noexcept
{
	uint16_t mtu;
	if (rte_eth_dev_get_mtu(port_id, &mtu))
	{
		return (rte_eth_dev_set_mtu(kni_port_, mtu) == 0);
	}
	return false;
}

bool KernelInterfaceHandle::SetupRxQueue(tQueueId queue, tSocketId socket, rte_mempool* mempool) noexcept
{
	int rc = rte_eth_rx_queue_setup(kni_port_,
	                                queue,
	                                queue_size_,
	                                socket,
	                                nullptr,
	                                mempool);
	if (rc < 0)
	{
		YADECAP_LOG_ERROR("rte_eth_rx_queue_setup(%u, %u) = %d\n", kni_port_, queue, rc);
		return false;
	}

	return true;
}

bool KernelInterfaceHandle::SetupTxQueue(tQueueId queue, tSocketId socket) noexcept
{
	int rc = rte_eth_tx_queue_setup(kni_port_,
	                                queue,
	                                queue_size_,
	                                socket,
	                                nullptr);
	if (rc < 0)
	{
		YADECAP_LOG_ERROR("rte_eth_tx_queue_setup(%u, %u) = %d\n", kni_port_, queue, rc);
		return false;
	}

	return true;
}

} // namespace dataplane