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
	/// Kernel neighbor state from rtnl_neigh_get_state():
	/// NUD_INCOMPLETE=0x01, NUD_REACHABLE=0x02, NUD_STALE=0x04,
	/// NUD_DELAY=0x08, NUD_PROBE=0x10, NUD_FAILED=0x20,
	/// NUD_NOARP=0x40, NUD_PERMANENT=0x80.
	int state = 0;

	std::string toString() const;
};

class Interface
{
public:
	virtual std::vector<Entry> GetHostDump(unsigned rcvbuf_size) = 0;
	virtual void StartMonitor(unsigned rcvbuf_size,
	                          // Last bool is renew_state: true only for NUD_REACHABLE/NUD_PERMANENT.
	                          std::function<void(std::string, const ipv6_address_t&, bool, const rte_ether_addr&, bool)> upsert,
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
	// Last bool is renew_state: true only for NUD_REACHABLE/NUD_PERMANENT.
	std::function<void(std::string, const ipv6_address_t&, bool, const rte_ether_addr&, bool)> upsert_;
	std::function<void(std::string, const ipv6_address_t&, bool)> remove_;
	std::function<void(std::string, const ipv6_address_t&, bool)> timestamp_;

	utils::Job monitor_;
	std::atomic<bool> failed_work_monitor_{false};

public:
	std::vector<Entry> GetHostDump(unsigned rcvbuf_size) final;
	void StartMonitor(unsigned rcvbuf_size,
	                  // Last bool is renew_state: true only for NUD_REACHABLE/NUD_PERMANENT.
	                  std::function<void(std::string, const ipv6_address_t&, bool, const rte_ether_addr&, bool)> upsert,
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