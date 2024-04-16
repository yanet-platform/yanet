#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <rte_ethdev.h>

#include "kernel_interface_handle.h"
namespace dataplane
{

bool KernelInterfaceHandle::SetUp() const
{
	int socket = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (socket < 0)
	{
		return false;
	}

	struct ifreq request;
	memset(&request, 0, sizeof request);

	strncpy(request.ifr_name, m_vdev_name.data(), IFNAMSIZ);

	request.ifr_flags |= IFF_UP;
	if (auto res = ioctl(socket, SIOCSIFFLAGS, &request))
	{
		YANET_LOG_ERROR("failed to set interface %s up, ioctl returned (%d)", m_vdev_name.data(), res);
		return false;
	}
	return true;
}

KernelInterfaceHandle::~KernelInterfaceHandle()
{
	if (Valid())
		Remove();
}
KernelInterfaceHandle::KernelInterfaceHandle(KernelInterfaceHandle&& other)
{
	*this = std::move(other);
}
bool KernelInterfaceHandle::Start() const
{
	auto rc = rte_eth_dev_start(m_kni_port);
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

KernelInterfaceHandle& KernelInterfaceHandle::operator=(KernelInterfaceHandle&& other)
{
	if (this != &other)
	{
		std::swap(m_kni_port, other.m_kni_port);
		std::swap(m_vdev_name, other.m_vdev_name);
	}
	return *this;
}

std::string KernelInterfaceHandle::vdevArgs(const std::string& name, const tPortId port_id, uint64_t queue_size)
{
	rte_ether_addr ether_addr;
	rte_eth_macaddr_get(port_id, &ether_addr);
	std::stringstream ss;
	ss << "path=/dev/vhost-net"
	   << ",queues=1"
	   << ",queue_size=" << queue_size
	   << ",iface=" << name.data()
	   << ",mac=" << common::mac_address_t(ether_addr.addr_bytes).toString().data();
	return ss.str();
}

bool KernelInterfaceHandle::Add(const std::string& vdev_name, const std::string& args)
{
	if (rte_eal_hotplug_add("vdev", vdev_name.data(), args.data()) != 0)
	{
		YADECAP_LOG_ERROR("failed to hotplug vdev interface '%s' with '%s'\n",
		                  vdev_name.data(),
		                  args.data());
		return false;
	}

	if (rte_eth_dev_get_port_by_name(vdev_name.data(), &m_kni_port) != 0)
	{
		YADECAP_LOG_ERROR("vdev interface '%s' not found\n", vdev_name.data());
		return false;
	}
	return true;
}
void KernelInterfaceHandle::Remove()
{
	rte_eal_hotplug_remove("vdev", m_vdev_name.data());
	MarkInvalid();
}

bool KernelInterfaceHandle::Configure(const rte_eth_conf& eth_conf)
{
	int ret = rte_eth_dev_configure(m_kni_port,
	                                1,
	                                1,
	                                &eth_conf);
	if (ret < 0)
	{
		YADECAP_LOG_ERROR("rte_eth_dev_configure() = %d\n", ret);
		return false;
	}
	return true;
}
bool KernelInterfaceHandle::CloneMTU(const uint16_t port_id) const
{
	uint16_t mtu;
	if (rte_eth_dev_get_mtu(port_id, &mtu) != 0)
		return false;

	rte_eth_dev_set_mtu(m_kni_port, mtu);
	return true;
}

bool KernelInterfaceHandle::SetupRxQueue(tQueueId queue, tSocketId socket, rte_mempool* mempool)
{
	int rc = rte_eth_rx_queue_setup(m_kni_port,
	                                queue,
	                                m_queue_size,
	                                socket,
	                                nullptr,
	                                mempool);
	if (rc < 0)
	{
		YADECAP_LOG_ERROR("rte_eth_rx_queue_setup(%u, %u) = %d\n", m_kni_port, 0, rc);
		return false;
	}

	return true;
}
bool KernelInterfaceHandle::SetupTxQueue(tQueueId queue, tSocketId socket)
{
	int rc = rte_eth_tx_queue_setup(m_kni_port,
	                                queue,
	                                m_queue_size,
	                                socket,
	                                nullptr);
	if (rc < 0)
	{
		YADECAP_LOG_ERROR("rte_eth_tx_queue_setup(%u, %u) = %d\n", m_kni_port, 0, rc);
		return false;
	}

	return true;
}

} // namespace dataplane