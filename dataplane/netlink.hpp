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
	tInterfaceId id;
	ipv6_address_t dst;
	std::optional<rte_ether_addr> mac;
	bool v6;
};

class Interface
{
public:
	virtual std::vector<Entry> GetHostDump(
	        const std::unordered_map<std::string, tInterfaceId>& ids) = 0;
	virtual void StartMonitor(std::function<std::optional<tInterfaceId>(const char*)> get_id,
	                          std::function<void(tInterfaceId, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert,
	                          std::function<void(tInterfaceId, const ipv6_address_t&, bool)> remove,
	                          std::function<void(tInterfaceId, const ipv6_address_t&, bool)> timestamp,
	                          std::function<void()> on_error) = 0;
	virtual void StopMonitor() = 0;
	virtual ~Interface() = default;
};

class Provider : public Interface
{
	static constexpr auto SOCKET_TIMEOUT = 100000;

	nl_sock* sk_;
	std::function<int(nl_msg*)> monitor_callback_;
	std::function<void(tInterfaceId, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert_;
	std::function<void(tInterfaceId, const ipv6_address_t&, bool)> remove_;
	std::function<void(tInterfaceId, const ipv6_address_t&, bool)> timestamp_;

	utils::Job monitor_;

public:
	std::vector<Entry> GetHostDump(
	        const std::unordered_map<std::string, tInterfaceId>& ids) final;
	void StartMonitor(std::function<std::optional<tInterfaceId>(const char*)> get_id,
	                  std::function<void(tInterfaceId, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert,
	                  std::function<void(tInterfaceId, const ipv6_address_t&, bool)> remove,
	                  std::function<void(tInterfaceId, const ipv6_address_t&, bool)> timestamp,
	                  std::function<void()> on_error) final;
	void StopMonitor() final;
	~Provider() final;
};

template<typename F>
int WrapAsCallback(nl_msg* msg, void* arg)
{
	auto* f = static_cast<F*>(arg);
	return f->operator()(msg);
}

} // namespace netlink
