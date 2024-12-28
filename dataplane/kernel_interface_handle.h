#pragma once

#include <rte_ethdev.h>

#include "common/type.h"

namespace dataplane
{

class KernelInterfaceHandle
{
	tPortId kni_port_ = INVALID_PORT_ID;
	std::string name_;
	std::string vdev_name_;
	uint16_t queue_size_ = 0;

	KernelInterfaceHandle() noexcept = default;

public:
	~KernelInterfaceHandle();
	KernelInterfaceHandle(const KernelInterfaceHandle&) = delete;
	KernelInterfaceHandle(KernelInterfaceHandle&& other) noexcept;
	KernelInterfaceHandle& operator=(const KernelInterfaceHandle&) = delete;
	KernelInterfaceHandle& operator=(KernelInterfaceHandle&& other) noexcept;
	[[nodiscard]] static std::optional<KernelInterfaceHandle>
	MakeKernelInterfaceHandle(std::string_view name,
	                          tPortId port,
	                          tQueueId queue_count,
	                          uint16_t queue_size) noexcept;
	[[nodiscard]] const tPortId& Id() const noexcept { return kni_port_; }
	[[nodiscard]] bool Start() const noexcept;
	[[nodiscard]] bool SetUp() const noexcept;
	bool SetupRxQueue(tQueueId queue, tSocketId socket, rte_mempool* mempool) noexcept;
	bool SetupTxQueue(tQueueId queue, tSocketId socket) noexcept;
	bool CloneMTU(const uint16_t) noexcept;

private:
	static std::string VdevName(std::string_view name, tPortId port_id);
	static std::string VdevArgs(std::string_view name, tPortId port_id, tQueueId queues_count, uint64_t queue_size);
	bool Add(const std::string& vdev_name, const std::string& args) noexcept;
	void Remove() noexcept;
	static rte_eth_conf DefaultConfig() noexcept;
	bool Configure(const rte_eth_conf& eth_conf, tQueueId queue_count) noexcept;
	void MarkInvalid() noexcept { kni_port_ = INVALID_PORT_ID; }
	[[nodiscard]] bool Valid() const { return kni_port_ != INVALID_PORT_ID; }
};

} // namespace dataplane
