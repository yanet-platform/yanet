#pragma once

#include <rte_ethdev.h>

#include "common.h"
#include "common/type.h"

namespace dataplane
{

class KernelInterfaceHandle
{
	tPortId m_kni_port = INVALID_PORT_ID;
	std::string m_vdev_name;
	uint16_t m_queue_size = 0;

	KernelInterfaceHandle() noexcept = default;

public:
	~KernelInterfaceHandle();
	KernelInterfaceHandle(const KernelInterfaceHandle&) = delete;
	KernelInterfaceHandle(KernelInterfaceHandle&& other) noexcept;
	[[nodiscard]] static std::optional<KernelInterfaceHandle>
	MakeKernelInterfaceHandle(
	        const std::string& name,
	        tPortId port,
	        uint16_t queue_size)
	{
		KernelInterfaceHandle kni;
		kni.m_queue_size = queue_size;
		kni.m_vdev_name = vdevName(name, port);
		std::string vdev_args = vdevArgs(name, port, queue_size);
		if (!kni.Add(kni.m_vdev_name, vdev_args) ||
		    !kni.Configure(DefaultConfig()))
		{
			return std::nullopt;
		}

		return std::optional<KernelInterfaceHandle>{std::move(kni)};
	}
	const tPortId& Id() const noexcept { return m_kni_port; }
	bool Start() const noexcept;
	KernelInterfaceHandle& operator=(const KernelInterfaceHandle&) = delete;
	KernelInterfaceHandle& operator=(KernelInterfaceHandle&& other) noexcept;
	[[nodiscard]] bool SetUp() const;
	bool SetupRxQueue(tQueueId queue, tSocketId socket, rte_mempool* mempool);
	bool SetupTxQueue(tQueueId queue, tSocketId socket);

private:
	static std::string vdevName(const std::string& name, const tPortId port_id)
	{
		std::stringstream ss;
		ss << "virtio_user_" << name << "_" << port_id;
		return ss.str();
	}
	static std::string vdevArgs(const std::string& name, const tPortId port_id, uint64_t queue_size);
	bool Add(const std::string& vdev_name, const std::string& args);
	void Remove();
	static rte_eth_conf DefaultConfig()
	{
		rte_eth_conf eth_conf;
		memset(&eth_conf, 0, sizeof(eth_conf));
		return eth_conf;
	}
	bool Configure(const rte_eth_conf& eth_conf) noexcept;
	bool CloneMTU(const uint16_t) const;
	void MarkInvalid() { m_kni_port = INVALID_PORT_ID; }
	[[nodiscard]] bool Valid() { return m_kni_port != INVALID_PORT_ID; }
};
} // namespace dataplane