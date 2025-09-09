#include <gtest/gtest.h>

#include <iostream>

#include "../neighbor.h"

namespace
{

class MockProvider final : public netlink::Interface
{
public:
	std::vector<netlink::Entry> GetHostDump(
	        const std::unordered_map<std::string, tInterfaceId>& ids)
	{
		return dump_;
	}
	void StartMonitor(std::function<std::optional<tInterfaceId>(const char*)> get_id,
	                  std::function<void(tInterfaceId, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert,
	                  std::function<void(tInterfaceId, const ipv6_address_t&, bool)> remove,
	                  std::function<void(tInterfaceId, const ipv6_address_t&, bool)> timestamp)
	{
		upsert_ = std::move(upsert);
		timestamp_ = std::move(timestamp);
		remove_ = std::move(remove);
	}
	void StopMonitor()
	{
	}
	~MockProvider() final = default;
	std::function<void(tInterfaceId, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert_;
	std::function<void(tInterfaceId, const ipv6_address_t&, bool)> timestamp_;
	std::function<void(tInterfaceId, const ipv6_address_t&, bool)> remove_;
	std::vector<netlink::Entry> dump_;
};

ipv6_address_t Ip6FromString(const char* s)
{
	ipv6_address_t result;
	common::ip_address_t com{s};
	if (com.is_ipv6())
	{
		inet_pton(AF_INET6, s, &result.bytes);
	}
	else
	{
		result.reset();
		inet_pton(AF_INET, s, &result.mapped_ipv4_address.address);
	}
	return result;
}

common::ip_address_t Common4FromString(const char* s)
{
	auto ip = Ip6FromString(s);
	std::array<uint8_t, 16> bytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	common::ip_address_t res(6, bytes.data());
	res = common::ip_address_t(4, ip.bytes);
	return res;
}

rte_ether_addr EthFromString(const char* s)
{
	rte_ether_addr addr;
	rte_ether_unformat_addr(s, &addr);
	return addr;
}

using entry_t = common::idp::neighbor_show::entry;
using response_t = common::idp::neighbor_show::response;

std::ostream& operator<<(std::ostream& os, entry_t e)
{
	os << std::get<0>(e) << ' '
	   << std::get<1>(e) << ' '
	   << std::get<common::ip_address_t>(e).toString() << ' '
	   << std::get<common::mac_address_t>(e).toString();
	if (auto& ts = std::get<4>(e))
	{
		os << ' ' << ts.value();
	}
	return os;
}

bool equal(entry_t a, entry_t b)
{
	return std::get<0>(a) == std::get<0>(b) &&
	       std::get<1>(a) == std::get<1>(b) &&
	       std::get<2>(a) == std::get<2>(b) &&
	       std::get<3>(a) == std::get<3>(b) &&
	       std::get<4>(a) == std::get<4>(b);
}

bool equal(response_t a, response_t b)
{
	std::size_t i = 0;
	while (i < a.size() && i < b.size())
	{
		if (!equal(a[i], b[i]))
		{
			std::cout << "a[" << i << "]: " << a[i] << "\n";
			std::cout << "  !=\n";
			std::cout << "b[" << i << "]: " << b[i] << "\n";
			return false;
		}
		++i;
	}
	if (i < a.size())
	{
		std::cout << "Extra: \n";
		std::cout << "a[" << i << "]: " << a[i] << "\n";
		return false;
	}
	if (i < b.size())
	{
		std::cout << "Extra: \n";
		std::cout << "b[" << i << "]: " << b[i] << "\n";
		return false;
	}
	return true;
}

TEST(NeighborTest, Basic)
{
	auto mock = new MockProvider;
	dataplane::neighbor::module dut(mock);
	auto now = 1;
	dut.init(
	        {1},
	        64 * 1024,
	        [](tSocketId) {
		        auto size = dataplane::neighbor::hashtable::calculate_sizeof(64 * 1024);
		        void* ptr = new char[size];
		        dataplane::neighbor::hashtable* ht = new (ptr) dataplane::neighbor::hashtable;
		        return ht;
	        },
	        [&]() { return now; },
	        []() {},
	        []() { return std::vector<dataplane::neighbor::key>{}; });

	dut.neighbor_update_interfaces({{1, "route0", "kni1"}});
	common::idp::neighbor_show::response expected = {
	        {"route0", "kni1", Common4FromString("192.168.1.1"), {"DE:AD:BE:EF:01:02"}, {1}}};
	dut.Upsert(1, Ip6FromString("192.168.1.1"), false, EthFromString("DE:AD:BE:EF:01:02"));

	now = 2;
	EXPECT_EQ(dut.neighbor_show(), expected);
	dut.neighbor_flush();
	EXPECT_EQ(dut.neighbor_show(), expected);
	dut.neighbor_flush();
	EXPECT_EQ(dut.neighbor_show(), expected);

	now = 3;
	dut.Upsert(1, Ip6FromString("100.200.1.2"), false, EthFromString("DE:AD:BE:EF:08:08"));
	expected = {
	        {"route0", "kni1", Common4FromString("192.168.1.1"), {"DE:AD:BE:EF:01:02"}, {2}},
	        {"route0", "kni1", Common4FromString("100.200.1.2"), {"DE:AD:BE:EF:08:08"}, {0}}};

	EXPECT_TRUE(equal(dut.neighbor_show(), expected));

	now = 4;
	dut.UpdateTimestamp(1, Ip6FromString("100.200.1.2"), false);
	expected = {
	        {"route0", "kni1", Common4FromString("192.168.1.1"), {"DE:AD:BE:EF:01:02"}, {3}},
	        {"route0", "kni1", Common4FromString("100.200.1.2"), {"DE:AD:BE:EF:08:08"}, {0}}};
	EXPECT_TRUE(equal(dut.neighbor_show(), expected));

	now = 5;
	dut.Remove(1, Ip6FromString("192.168.1.1"), false);
	expected = {
	        {"route0", "kni1", Common4FromString("100.200.1.2"), {"DE:AD:BE:EF:08:08"}, {1}}};
	EXPECT_TRUE(equal(dut.neighbor_show(), expected));

	dut.neighbor_flush();
	EXPECT_TRUE(equal(dut.neighbor_show(), expected));

	dut.neighbor_clear();
	EXPECT_TRUE(equal(dut.neighbor_show(), {}));
}

TEST(NeighborTest, Provider)
{
	auto mock = new MockProvider;
	dataplane::neighbor::module dut(mock);
	auto now = 1;
	dut.init(
	        {1},
	        64 * 1024,
	        [](tSocketId) {
		        auto size = dataplane::neighbor::hashtable::calculate_sizeof(64 * 1024);
		        void* ptr = new char[size];
		        dataplane::neighbor::hashtable* ht = new (ptr) dataplane::neighbor::hashtable;
		        return ht;
	        },
	        [&]() { return now; },
	        []() {},
	        []() { return std::vector<dataplane::neighbor::key>{}; });

	dut.neighbor_update_interfaces({{1, "route0", "kni1"}});
	dut.neighbor_clear();
	EXPECT_TRUE(equal(dut.neighbor_show(), {}));

	mock->dump_ = {
	        {1, Ip6FromString("192.168.1.1"), EthFromString("DE:AD:BE:EF:01:02"), false},
	        {1, Ip6FromString("100.200.1.2"), EthFromString("DE:AD:BE:EF:08:08"), false}};

	dut.neighbor_clear();

	common::idp::neighbor_show::response expected = {
	        {"route0", "kni1", Common4FromString("192.168.1.1"), {"DE:AD:BE:EF:01:02"}, {0}},
	        {"route0", "kni1", Common4FromString("100.200.1.2"), {"DE:AD:BE:EF:08:08"}, {0}}};
	EXPECT_TRUE(equal(dut.neighbor_show(), expected));
}

} // namespace