#pragma once
#include <string>
#include <unordered_map>
#include <vector>

#include "common/type.h"
#include "common/utils.h"
#include "dataplane/type.h"

struct nl_msg;
struct nl_sock;

namespace netlink
{

struct Entry
{
	std::string ifname;
	ipv6_address_t dst;
	std::optional<rte_ether_addr> mac;
	bool v6;

	std::string toString() const;
};

class Interface
{
public:
	virtual std::vector<Entry> GetHostDump(unsigned rcvbuf_size) = 0;
	virtual void StartMonitor(unsigned rcvbuf_size,
	                          std::function<void(std::string, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert,
	                          std::function<void(std::string, const ipv6_address_t&, bool)> remove,
	                          std::function<void(std::string, const ipv6_address_t&, bool)> timestamp) = 0;
	virtual void StopMonitor() = 0;
	virtual ~Interface() = default;
	virtual bool IsFailedWorkMonitor() = 0;
};

class Provider : public Interface
{
	static constexpr auto SOCKET_TIMEOUT = 100000;

	nl_sock* sk_;
	std::function<int(nl_msg*)> monitor_callback_;
	std::function<void(std::string, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert_;
	std::function<void(std::string, const ipv6_address_t&, bool)> remove_;
	std::function<void(std::string, const ipv6_address_t&, bool)> timestamp_;

	utils::Job monitor_;
	std::atomic<bool> failed_work_monitor_{false};

public:
	std::vector<Entry> GetHostDump(unsigned rcvbuf_size) final;
	void StartMonitor(unsigned rcvbuf_size,
	                  std::function<void(std::string, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert,
	                  std::function<void(std::string, const ipv6_address_t&, bool)> remove,
	                  std::function<void(std::string, const ipv6_address_t&, bool)> timestamp) final;
	void StopMonitor() final;
	~Provider() final;
	bool IsFailedWorkMonitor() final;
};

template<typename F>
int WrapAsCallback(nl_msg* msg, void* arg)
{
	auto* f = static_cast<F*>(arg);
	return f->operator()(msg);
}

} // namespace netlink