#include <array>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "../acl.h"
#include "../acl/dispatcher.h"

namespace
{

using common::ipv4_address_t;
using common::globalBase::eFlowType;

auto make_default_acl(const std::string& rules, tAclId aclId = 1) -> controlplane::base::acl_t
{
	controlplane::base::acl_t acl;
	common::globalBase::tFlow flow{};
	flow.type = common::globalBase::eFlowType::route;

	acl.aclId = aclId;
	acl.nextModules = {"unmatched"};
	acl.nextModuleRules.emplace_back(flow);

	acl.firewall = std::make_shared<ipfw::fw_config_t>(2);
	acl.firewall->schedule_string(rules);
	acl.firewall->parse();
	acl.firewall->validate();

	return acl;
}

auto generate_firewall_conf(std::size_t size) -> nlohmann::json
{
	if (size < 2)
	{
		throw std::logic_error("`size` must be >= 2");
	}

	std::string rules(R"IPFW(
:BEGIN
add skipto :IN ip from any to any in

:IN
)IPFW");

	// Subtract by the number of predefined rules.
	size -= 2;
	for (unsigned i = 0; i < size; ++i)
	{
		std::ostringstream s;
		s << "add allow tcp from any to { "
		  << "2abc:123:ff1c:" << std::setw(4) << std::setfill('0') << std::hex << i + 1 << "::/ffff:ffff:ffff:ffff::"
		  << " } dst-port " << std::dec << i + 1 << std::endl;
		rules.append(s.str());
	}

	rules.append(R"IPFW(
add allow tcp from any to any established
add deny ip from any to any
)IPFW");

	return rules;
}

TEST(ACL, 001_Basic)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add skipto :IN ip from any to any in

:IN
add allow tcp from { 2abc:123:ff1c:2030::/ffff:ffff:ffff:fff0:: } to any 80
add allow tcp from { 2abc:123:ff1c:2030::/ffff:ffff:ffff:ffff:: } to any 81
add allow tcp from { 2abc:123:ff1c:2030::/ffff:ffff:ffff:fff0:: or 2abc:123:ff1c:2030:0:4321::/ffff:ffff:ffff:fff0:ffff:ffff:: } to any 82
add allow tcp from { 2abc:123:ff1c:2030:0:5678::/ffff:ffff:ffff:fff0:ffff:ffff:: } to any 83
add allow tcp from { 2abc:123:ff1c:2030:aabb:5678::/ffff:ffff:ffff:fff0:ffff:ffff:: } to any 84
add deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
}

TEST(ACL, 002_IPv4Only)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add skipto :IN ip from any to any in

:IN
add allow tcp from { 1.2.3.4 } to any dst-port 80
add deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
}

TEST(ACL, 003_Over500)
{
	auto fw = make_default_acl(generate_firewall_conf(500));

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
}

TEST(ACL, 004_Over1000)
{
	auto fw = make_default_acl(generate_firewall_conf(1000));

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
}

TEST(ACL, 005_Over4000)
{
	auto fw = make_default_acl(generate_firewall_conf(4000));

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
}

TEST(ACL, 006_Counters)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 1 skipto :IN ip from any to any in

:IN
add 2 skipto :A_IN ip from { 1.2.3.4 } to any
add 3 skipto :A_IN ip from { 1.2.3.6 } to any
add 4 deny ip from any to any

:A_IN
add 5 allow tcp from { 1.2.3.4 } to any dst-port 80
add 6 allow tcp from { 1.2.3.5 } to any dst-port 80
add 7 deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 5);
	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;

		const auto& value = result.acl_values[total_table_value];
		EXPECT_THAT(value.flow.counter_id, ::testing::Ge(1));
		EXPECT_THAT(value.flow.counter_id, ::testing::Lt(5));
	}
	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1, 2, 5));
	EXPECT_THAT(ids_map[2], ::testing::ElementsAre(1, 2, 7));
	EXPECT_THAT(ids_map[3], ::testing::ElementsAre(1, 3, 7));
	EXPECT_THAT(ids_map[4], ::testing::ElementsAre(1, 4));
}

TEST(ACL, 007_OrderDeny)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 1 deny ip from any to any in
add 2 allow ip from { 1.2.3.4 } to any in
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	auto& ids_map = result.ids_map;
	ASSERT_EQ(result.acl_total_table.size(), 1);
	ASSERT_EQ(ids_map.size(), 2);
	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;

		const auto& value = result.acl_values[total_table_value];
		EXPECT_THAT(value.flow.type, ::testing::Eq(common::globalBase::eFlowType::drop));
	}
	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
}

TEST(ACL, 008_OrderAllow)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 1 allow ip from { 1.2.3.4 } to any in
add 2 deny ip from any to any in
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	auto& ids_map = result.ids_map;
	ASSERT_EQ(result.acl_total_table.size(), 2);
	ASSERT_EQ(ids_map.size(), 3);

	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
	EXPECT_THAT(ids_map[2], ::testing::ElementsAre(2));
}

TEST(ACL, 010_Via)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 1 allow ip from { 1.2.3.4 } to any in via port0
add 2 deny ip from any to any in
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "port0"}, {true, "port1"}}}}, result);

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 3);
	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
	EXPECT_THAT(ids_map[2], ::testing::ElementsAre(2));

	auto& ifaces = result.in_iface_map;
	ASSERT_EQ(ifaces.size(), 2);
	EXPECT_THAT(ifaces["port0"], 1);
	EXPECT_THAT(ifaces["port1"], 2);

	auto& acl_map = result.acl_map;
	ASSERT_EQ(acl_map.size(), 1);
	EXPECT_THAT(acl_map[1], ::testing::ElementsAre(1, 2));
}

TEST(ACL, 011_ViaOut)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add allow ip from { 1.2.3.4 } to any out via port0 // id 1
add allow ip from { 1.2.3.5 } to any out via port1 // id 2
add deny ip from any to any out // id 3
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{false, "port0"}, {false, "port1"}, {false, "port2"}, {false, "port3"}}}}, result);

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 4);
	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
	EXPECT_THAT(ids_map[2], ::testing::ElementsAre(3));
	EXPECT_THAT(ids_map[3], ::testing::ElementsAre(2));

	auto& ifaces = result.out_iface_map;
	ASSERT_EQ(ifaces.size(), 4);
	EXPECT_THAT(ifaces["port0"], 1);
	EXPECT_THAT(ifaces["port1"], 2);
	EXPECT_THAT(ifaces["port2"], 3);
	EXPECT_THAT(ifaces["port3"], 3);
}

TEST(ACL, 012_Lookup)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add skipto :ALL ip from any to any // id 1

:ALL
add allow ip from { 1.2.3.4 } to any out via port0 // id 2
add allow log ip from { 1.2.3.5 } to any out via port1 // id 3
add deny ip from any to any out // id 4
add allow ip from any to any in // id 5
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};

	auto ret = acl::unwind(acls, {{1, {{false, "port0"}, {false, "port1"}, {false, "port2"}, {false, "port3"}, {true, "port0"}}}}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});
	ASSERT_EQ(ret.size(), 6);

	std::set<std::string> expect = {"port2 port3 |1|any|any|any|any|any|any|any|false|drop(0)|1, 4|false|",
	                                "port0 |1|1.2.3.4/255.255.255.255|any|any|any|any|any|any|false|logicalPort_egress(0)|1, 2|false|",
	                                "port0 |1|any|any|any|any|any|any|any|false|drop(0)|1, 4|false|",
	                                "port0 |0|any|any|any|any|any|any|any|false|route(0)|1, 5|false|",
	                                "port1 |1|1.2.3.5/255.255.255.255|any|any|any|any|any|any|false|logicalPort_egress(0)|1, 3|true|",
	                                "port1 |1|any|any|any|any|any|any|any|false|drop(0)|1, 4|false|"};

	auto stringify = [](auto& v) { return std::apply([](auto... e) { return (((e ? *e : "any") + "|") + ...); }, v); };

	for (const auto& r : ret)
	{
		auto str = stringify(r);

		std::cout << str << std::endl;
		EXPECT_THAT(expect.count(str), 1) << "No matching string for " << str;
	}
}

TEST(ACL, 013_DefaultAction)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 1 allow icmp from { 1.2.3.4 } to any in
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};

	auto ret = acl::unwind(acls, {{1, {{true, "vlan1"}, {false, "vlan1"}}}}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});
	ASSERT_EQ(ret.size(), 3);

	auto stringify = [](auto& v) { return std::apply([](auto... e) { return (((e ? *e : "any") + "|") + ...); }, v); };

	EXPECT_THAT(stringify(ret[0]), ::testing::Eq("vlan1 |0|1.2.3.4/255.255.255.255|any|any|1|any|any|any|false|route(0)|1|false|"));
	EXPECT_THAT(stringify(ret[1]), ::testing::Eq("vlan1 |0|any|any|any|any|any|any|any|false|route(0)||false|"));
	EXPECT_THAT(stringify(ret[2]), ::testing::Eq("vlan1 |1|any|any|any|any|any|any|any|false|logicalPort_egress(0)||false|"));

	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}, {false, "vlan1"}}}}, result);

	auto& ids_map = result.ids_map;
	ASSERT_EQ(result.acl_total_table.size(), 4);
	ASSERT_EQ(ids_map.size(), 2);

	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
}

TEST(ACL, 014_Log)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 allow log ip from { 1.2.3.4 } to any in via port0
add 200 deny log ip from any to any in
add 300 deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};

	auto ret = acl::unwind(acls, {{1, {{true, "port0"}, {true, "port1"}}}}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});
	ASSERT_EQ(ret.size(), 3);

	auto stringify = [](auto& v) { return std::apply([](auto... e) { return (((e ? *e : "any") + "|") + ...); }, v); };

	EXPECT_THAT(stringify(ret[0]), ::testing::Eq("port1 |0|any|any|any|any|any|any|any|false|drop(0)|2|true|"));
	EXPECT_THAT(stringify(ret[1]), ::testing::Eq("port0 |0|1.2.3.4/255.255.255.255|any|any|any|any|any|any|false|route(0)|1|true|"));
	EXPECT_THAT(stringify(ret[2]), ::testing::Eq("port0 |0|any|any|any|any|any|any|any|false|drop(0)|2|true|"));

	acl::result_t result;
	acl::compile(acls, {{1, {{true, "port0"}, {true, "port1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 4);
	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;
		EXPECT_THAT(result.acl_values[total_table_value].flow.flags, ::testing::Eq((uint8_t)common::globalBase::eFlowFlags::log));
	}

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 3);
	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
	EXPECT_THAT(ids_map[2], ::testing::ElementsAre(2));

	auto& ifaces = result.in_iface_map;
	ASSERT_EQ(ifaces.size(), 2);
	EXPECT_THAT(ifaces["port0"], 1);
	EXPECT_THAT(ifaces["port1"], 2);

	auto& acl_map = result.acl_map;
	ASSERT_EQ(acl_map.size(), 1);
	EXPECT_THAT(acl_map[1], ::testing::ElementsAre(1, 2));

	ASSERT_EQ(result.rules.size(), 3);
	EXPECT_THAT(std::get<2>(result.rules[100].front()), ::testing::Eq("allow log ip from { 1.2.3.4 } to any in via port0"));
	EXPECT_THAT(std::get<2>(result.rules[200].front()), ::testing::Eq("deny log ip from any to any in"));
	EXPECT_THAT(std::get<2>(result.rules[300].front()), ::testing::Eq("deny ip from any to any"));
}

TEST(ACL, 015_GappedMask)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 allow proto tcp dst-addr 4242@2abc:123:c00::/40
add 200 allow proto tcp dst-addr fc00/23@2abc:123:c00::/40
add 300 allow proto tcp dst-addr 1234567@2abc:123:c00::/40
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};

	auto ret = acl::unwind(acls, {{1, {{true, "vlan1"}}}}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});
	ASSERT_EQ(ret.size(), 4);

	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
	// check that parser correctly expands gapped mask in rules -> compare with generated text
	EXPECT_THAT(std::get<1>(result.rules[100].front()), ::testing::Eq("allow dst-addr 2abc:123:c00::4242:0:0/ffff:ffff:ff00:0:ffff:ffff:: proto 6"));
	EXPECT_THAT(std::get<1>(result.rules[200].front()), ::testing::Eq("allow dst-addr 2abc:123:c00::fc00:0:0/ffff:ffff:ff00:0:ffff:fe00:: proto 6"));
	EXPECT_THAT(std::get<1>(result.rules[300].front()), ::testing::Eq("allow dst-addr 2abc:123:c00:0:123:4567::/ffff:ffff:ff00:0:ffff:ffff:: proto 6"));
}

TEST(ACL, 016_TcpFlags)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 deny tcp from any to any setup
add 150 deny tcp from any to any tcpflags syn,!ack // the same as setup
add 200 deny tcp from any to any tcpflags fin,psh,urg
add 300 deny tcp from any to any tcpflags !syn,!fin,!ack,!psh,!rst,!urg
add 400 allow tcp from any to any tcpflags rst
add 500 allow tcp from any to any established
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};

	auto ret = acl::unwind(acls, {{1, {{true, "vlan1"}}}}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});
	ASSERT_EQ(ret.size(), 7);

	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
	// check that parser correctly expands tcpflags and then filter correctly formats them
	EXPECT_THAT(std::get<1>(result.rules[100].front()), ::testing::Eq("deny proto 6 setup"));
	EXPECT_THAT(std::get<1>(result.rules[150].front()), ::testing::Eq("deny proto 6 setup"));
	EXPECT_THAT(std::get<1>(result.rules[200].front()), ::testing::Eq("deny proto 6 tcpflags fin,psh,urg"));
	EXPECT_THAT(std::get<1>(result.rules[300].front()), ::testing::Eq("deny proto 6 tcpflags !fin,!syn,!rst,!psh,!ack,!urg"));
	EXPECT_THAT(std::get<1>(result.rules[400].front()), ::testing::Eq("allow proto 6 tcpflags rst"));
	EXPECT_THAT(std::get<1>(result.rules[500].front()), ::testing::Eq("allow proto 6 etsablished"));
}

TEST(ACL, 017_IcmpTypes)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 allow icmp from any to any icmptypes 0,8,3,11,12
# parser automatically inserts ICMP or ICMPv6 protocol
# when it is not specified
add 200 deny ip from any to any icmptypes 1,2,3,9,10,13
add 300 allow ip from any to any icmp6types 133,134,135,136
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};

	auto ret = acl::unwind(acls, {{1, {{true, "vlan1"}}}}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});
	ASSERT_EQ(ret.size(), 4);

	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
	// check that parser correctly expands icmptypes and then filter correctly formats them
	EXPECT_THAT(std::get<1>(result.rules[100].front()), ::testing::Eq("allow proto 1 icmptypes 0,3,8,11,12"));
	EXPECT_THAT(std::get<1>(result.rules[200].front()), ::testing::Eq("deny proto 1 icmptypes 1,2,3,9,10,13"));
	EXPECT_THAT(std::get<1>(result.rules[300].front()), ::testing::Eq("allow proto 58 icmp6types 133,134,135,136"));
}

TEST(ACL, 018_EmptyDst)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 allow icmp from any to unknown.hostname.tld icmptypes 0,8
add 200 deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};

	auto ret = acl::unwind(acls, {{1, {{true, "vlan1"}}}}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});
	ASSERT_EQ(ret.size(), 1);

	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);
	// we expect that after validation rule 100 will be omitted and only one rule will remain
	EXPECT_THAT(std::get<1>(result.rules[200].front()), ::testing::Eq("deny"));
}

using namespace acl;

ref_t<filter_t> empty_filter()
{
	return new filter_t(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

ref_t<filter_network_t> destinations(std::initializer_list<std::string> networks)
{
	ref_t<filter_network_t> result = new filter_network_t;
	for (const auto& network : networks)
	{
		result->networks.emplace_back(network);
	}
	return result;
}

ref_t<filter_t> destination_filter(const ref_t<filter_network_t>& dst, const ref_t<filter_id_t>& dir = nullptr)
{
	auto result = empty_filter();
	result->dst = dst;
	result->dir = dir;
	return result;
}

ref_t<filter_proto_t> eager_protocol(const ref_t<filter_proto_t>& a, const ref_t<filter_proto_t>& b)
{
	if (!a || !b)
	{
		return a ? a : b;
	}
	return new filter_proto_t(a->type & b->type, a->prm1 & b->prm1, a->prm2 & b->prm2, a->prm3 & b->prm3);
}

ref_t<filter_t> eager_filter(const ref_t<filter_t>& a, const ref_t<filter_t>& b)
{
	if (!a || !b)
	{
		return a ? a : b;
	}
	return new filter_t(a->acl_id & b->acl_id,
	                    a->src & b->src,
	                    a->dst & b->dst,
	                    a->flags & b->flags,
	                    eager_protocol(a->proto, b->proto),
	                    a->dir & b->dir,
	                    a->keepstate & b->keepstate);
}

void expect_same_filter(const ref_t<filter_t>& actual, const ref_t<filter_t>& expected)
{
	ASSERT_EQ(actual.is_none(), expected.is_none());
	if (expected.is_none())
	{
		EXPECT_TRUE(actual); // nullptr is the unrestricted identity, not failure.
		return;
	}
	EXPECT_EQ(actual, expected);
	if (actual && expected)
	{
		EXPECT_EQ(actual->acl_id, expected->acl_id); // filter equality omits ACL IDs.
	}
}

TEST(ACLUnwind, StagedIntersectionMatchesEager)
{
	std::vector<ref_t<filter_proto_t>> protocols{nullptr};
	for (int field = 0; field < 4; ++field)
	{
		for (int value = 0; value < 3; ++value)
		{
			ref_t<filter_proto_t> proto = new filter_proto_t(nullptr, nullptr, nullptr, nullptr);
			if (field == 0 || field == 3)
			{
				ref_t<filter_prm8_t> prm = new filter_prm8_t;
				if (value)
				{
					// Unsorted, multiple and overlapping closed ranges must retain order.
					prm->ranges = {{17, 20}, {6, 8}, {7, unsigned(value == 1 ? 9 : 17)}};
				}
				(field == 0 ? proto->type : proto->prm3) = prm;
			}
			else
			{
				ref_t<filter_prm16_t> prm = new filter_prm16_t;
				if (value)
				{
					prm->ranges = {{443, 445}, {80, unsigned(value == 1 ? 81 : 443)}};
				}
				(field == 1 ? proto->prm1 : proto->prm2) = prm;
			}
			protocols.push_back(proto);
		}
	}
	protocols.push_back(new filter_proto_t(new filter_prm8_t(6), new filter_prm16_t(80), new filter_prm16_t(443), new filter_prm8_t(2)));
	protocols.push_back(new filter_proto_t(new filter_prm8_t(17), new filter_prm16_t(53), new filter_prm16_t(53), new filter_prm8_t(16)));
	for (const auto& a : protocols)
	{
		for (const auto& b : protocols)
		{
			const auto expected = eager_protocol(a, b);
			const auto actual = a & b;
			ASSERT_EQ(actual.is_none(), expected.is_none());
			if (expected.is_none())
			{
				EXPECT_TRUE(actual);
			}
			else
			{
				EXPECT_EQ(actual, expected);
			}
			if (!a || !b)
			{
				EXPECT_EQ(actual.filter, expected.filter);
			}
		}
	}

	std::vector<ref_t<filter_t>> filters{nullptr, empty_filter()};
	for (const auto& proto : protocols)
	{
		auto filter = empty_filter();
		filter->proto = proto;
		filters.push_back(filter);
	}
	for (int field = 0; field < 7; ++field)
	{
		for (int value = 0; value < 3; ++value)
		{
			auto filter = empty_filter();
			switch (field)
			{
				case 0:
					filter->acl_id = new filter_id_t(value - 1);
					break;
				case 1:
					filter->dir = new filter_id_t(value - 1);
					break;
				case 2:
					filter->keepstate = value ? new filter_bool_t(value - 1) : new filter_bool_t;
					break;
				case 3:
					filter->flags = value ? new filter_prm8_t(value) : new filter_prm8_t;
					break;
				default:
				{
					auto networks = value ? destinations({value == 1 ? "10.0.0.7/24" : "2001:db8::7/64"}) : destinations({});
					(field == 4 ? filter->dst : filter->src) = networks;
					if (field == 6)
					{
						filter->acl_id = new filter_id_t(1);
						filter->dir = new filter_id_t(0);
						filter->proto = protocols.back();
					}
				}
			}
			filters.push_back(filter);
		}
	}
	for (const auto offset : {0, 1})
	{
		auto filter = empty_filter();
		filter->acl_id = new filter_id_t(42);
		filter->dir = new filter_id_t(0);
		filter->src = destinations({"2001:db8::7/64", "10.0.0.7/24", "10.0.0.8/28"});
		filter->dst = destinations({"10.0.0.9/255.255.255.250", "2001:db8::9/124", "10.0.0.9/28"});
		filter->proto = new filter_proto_t(new filter_prm8_t(6),
		                                   new filter_prm16_t(acl::range_t<uint16_t>(80 + offset, 90)),
		                                   new filter_prm16_t(443),
		                                   new filter_prm8_t(offset));
		filter->flags = new filter_prm8_t(offset);
		filter->keepstate = new filter_bool_t(1);
		filters.push_back(filter);
	}
	for (const auto& a : filters)
	{
		for (const auto& b : filters)
		{
			const auto expected = eager_filter(a, b);
			const auto actual = a & b;
			expect_same_filter(actual, expected);
			if (!a || !b)
			{
				EXPECT_EQ(actual.filter, expected.filter);
			}
			if (a && b && !expected.is_none())
			{
				EXPECT_TRUE(compatible(a, b));
			}
		}
	}
}

TEST(ACLUnwind, CheapCompatibilityRejections)
{
	auto a = empty_filter();
	auto b = empty_filter();
	a->acl_id = new filter_id_t(1);
	b->acl_id = new filter_id_t(2);
	EXPECT_FALSE(compatible(a, b));
	b->acl_id = nullptr;
	a->dir = new filter_id_t(0);
	b->dir = new filter_id_t(1);
	EXPECT_FALSE(compatible(a, b));
	b->dir = nullptr;
	a->proto = new filter_proto_t(new filter_prm8_t, nullptr, nullptr, nullptr);
	b->proto = new filter_proto_t(new filter_prm8_t, nullptr, nullptr, nullptr);
	a->proto->type->ranges = {{17, 20}, {6, 8}};
	b->proto->type->ranges = {{50, 60}, {8, 9}};
	EXPECT_TRUE(compatible(a, b)); // Inclusive endpoint, not just the first range.
	b->proto->type->ranges = {{50, 60}, {9, 16}};
	EXPECT_FALSE(compatible(a, b));
	b->proto->type->ranges.clear();
	EXPECT_FALSE(compatible(a, b));
	b->proto->type = nullptr;
	EXPECT_TRUE(compatible(a, b));
}

void add_dispatcher_rule(std::vector<rule_t>& rules, const ref_t<filter_t>& filter, eFlowType type = eFlowType::route)
{
	common::globalBase::tFlow flow(type);
	flow.data.atomic = rules.size();
	flow.counter_id = rules.size();
	flow.flags = rules.size() % 4;
	rules.emplace_back(filter, flow, ids_t(), rules.size() % 2);
}

// dispatcher_fixture layout: a leading wildcard, per-host rules, then fallbacks.
constexpr size_t WILDCARD_RULES = 1;
constexpr std::array<int, 2> FAMILIES{4, 6};
constexpr std::array<int, 3> PROTOCOLS{6, 17, 6};
constexpr size_t RULES_PER_HOST = FAMILIES.size() * PROTOCOLS.size();

size_t first_host_rule(size_t host)
{
	return WILDCARD_RULES + host * RULES_PER_HOST;
}

std::vector<rule_t> dispatcher_fixture(size_t hosts)
{
	std::vector<rule_t> rules;
	// A nonterminal wildcard must stay before the indexed hosts.
	auto wildcard = empty_filter();
	wildcard->proto = new filter_proto_t(new filter_prm8_t(6), nullptr, nullptr, nullptr);
	wildcard->dir = new filter_id_t(0);
	add_dispatcher_rule(rules, wildcard);
	for (size_t host = 0; host < hosts; ++host)
	{
		for (const auto family : FAMILIES)
		{
			for (const auto protocol : PROTOCOLS)
			{
				ref_t<filter_network_t> dst = new filter_network_t;
				const auto addr = family == 4 ? uint128_t(0x0a000000 + host) : (uint128_t(0x20010db8) << 96) + host;
				const auto mask = family == 4 ? uint128_t(uint32_t(-1)) : uint128_t(-1);
				dst->networks.emplace_back(family, addr, mask);
				auto filter = destination_filter(dst, new filter_id_t(0));
				filter->proto = new filter_proto_t(new filter_prm8_t(protocol), nullptr, new filter_prm16_t(80 + rules.size() % 2), nullptr);
				add_dispatcher_rule(rules, filter);
			}
		}
	}
	add_dispatcher_rule(rules, destination_filter(destinations({"10.0.0.5/24"}), new filter_id_t(0)));
	add_dispatcher_rule(rules, destination_filter(destinations({"2001:db8::5/64"}), new filter_id_t(0)));
	add_dispatcher_rule(rules, destination_filter(destinations({"10.0.0.7", "2001:db8::7"}), new filter_id_t(0)));
	add_dispatcher_rule(rules, destination_filter(destinations({"10.0.0.7"})));
	add_dispatcher_rule(rules, destination_filter(destinations({"10.0.0.7"}), new filter_id_t(1)));
	add_dispatcher_rule(rules, destination_filter(destinations({}), new filter_id_t(0)));
	add_dispatcher_rule(rules, destination_filter(nullptr, new filter_id_t(0)), eFlowType::drop);
	add_dispatcher_rule(rules, destination_filter(nullptr, new filter_id_t(1)), eFlowType::logicalPort_egress);
	return rules;
}

// Gathers a match like unwind_dispatcher; returns whether the rule terminates the scan.
bool gather(std::vector<rule_t>& result, const rule_t& rule, const ref_t<filter_t>& intersection)
{
	ids_t ids{900};
	ids.insert(ids.end(), rule.ids.begin(), rule.ids.end());
	result.emplace_back(intersection, std::get<common::globalBase::tFlow>(rule.action), ids, rule.log);
	return !rule.filter || (!rule.filter->src && !rule.filter->dst && !rule.filter->flags && !rule.filter->proto);
}

// Original network-only rejection, eager intersection and terminal behavior.
std::vector<rule_t> evaluate_dispatcher(const std::vector<rule_t>& rules,
                                        const ref_t<filter_t>& filter)
{
	std::vector<rule_t> result;
	for (const auto& rule : rules)
	{
		if (filter && rule.filter &&
		    (!compatible(filter->dst, rule.filter->dst) || !compatible(filter->src, rule.filter->src)))
		{
			continue;
		}
		const auto intersection = eager_filter(filter, rule.filter);
		if (!intersection.is_none() && gather(result, rule, intersection))
		{
			break;
		}
	}
	return result;
}

std::vector<rule_t> evaluate_indexed_dispatcher(const std::vector<rule_t>& rules,
                                                const ref_t<filter_t>& filter,
                                                const dispatcher_index_t& index)
{
	std::vector<rule_t> result;
	const auto candidates = index.candidates(filter);
	const auto count = candidates ? candidates->size() : rules.size();
	for (size_t i = 0; i < count; ++i)
	{
		const auto& rule = rules[candidates ? (*candidates)[i] : i];
		if (!compatible(filter, rule.filter))
		{
			continue;
		}
		const auto intersection = filter & rule.filter;
		if (!intersection.is_none() && gather(result, rule, intersection))
		{
			break;
		}
	}
	return result;
}

void expect_same_dispatcher(const std::vector<rule_t>& rules, const dispatcher_index_t& index, const ref_t<filter_t>& query)
{
	const auto expected = evaluate_dispatcher(rules, query);
	const auto actual = evaluate_indexed_dispatcher(rules, query, index);
	ASSERT_EQ(actual.size(), expected.size());
	for (size_t i = 0; i < actual.size(); ++i)
	{
		EXPECT_EQ(actual[i], expected[i]);
		EXPECT_EQ(actual[i].ids, expected[i].ids); // rule equality omits IDs.
		expect_same_filter(actual[i].filter, expected[i].filter);
	}
}

TEST(ACLUnwind, IndexedDispatcherMatchesLinear)
{
	auto rules = dispatcher_fixture(64);
	// IPv4 masks occupy only the low 32 bits of the uint128 representation.
	rules[first_host_rule(7)].filter->dst->networks.front().addr |= uint128_t(1) << 80;
	const dispatcher_index_t index(rules);
	// Simulate the later assignment of debug dispatcher IDs.
	for (size_t i = 0; i < rules.size(); ++i)
	{
		rules[i].ids = {uint32_t(1000 + i)};
	}
	std::vector<ref_t<filter_network_t>> queries{
	        nullptr,
	        destinations({}),
	        destinations({"10.0.0.7"}),
	        destinations({"2001:db8::7"}),
	        destinations({"10.0.0.7/28", "10.0.0.7", "10.0.0.9/29", "10.0.0.7/28", "2001:db8::7/124"}),
	        destinations({"10.0.0.0/255.255.255.250"}),
	        destinations({"2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffa"}),
	        destinations({"0.0.0.0/0", "::/0"}),
	        destinations({"192.0.2.1"}),
	        destinations({"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"})};
	ref_t<filter_network_t> unsupported = new filter_network_t;
	unsupported->networks.emplace_back(7, 0, 0);
	queries.push_back(unsupported);
	ref_t<filter_network_t> invalid_mask = new filter_network_t;
	invalid_mask->networks.emplace_back(4, 7, uint128_t(1) << 40);
	queries.push_back(invalid_mask);
	for (const auto& dst : queries)
	{
		for (const auto dir : {-2, -1, 0, 1})
		{
			auto query = destination_filter(dst, dir == -2 ? nullptr : new filter_id_t(dir));
			query->acl_id = new filter_id_t(42);
			expect_same_dispatcher(rules, index, query);
			query->proto = new filter_proto_t(new filter_prm8_t(6), nullptr, new filter_prm16_t(80), nullptr);
			expect_same_dispatcher(rules, index, query);
		}
	}
	expect_same_dispatcher(rules, index, nullptr);
	EXPECT_FALSE(index.candidates(nullptr));
	EXPECT_FALSE(index.candidates(empty_filter()));
	EXPECT_FALSE(index.candidates(destination_filter(unsupported)));
	EXPECT_FALSE(index.candidates(destination_filter(invalid_mask)));
	const auto empty = index.candidates(destination_filter(destinations({})));
	ASSERT_TRUE(empty);
	EXPECT_TRUE(empty->empty());

	const auto gapped = destination_filter(destinations({"10.0.0.0/255.255.255.250"}), new filter_id_t(0));
	const auto candidates = index.candidates(gapped);
	ASSERT_TRUE(candidates);
	// .2 lies inside the conservative interval but conflicts with a fixed mask bit.
	const size_t false_positive = first_host_rule(2);
	EXPECT_NE(std::find(candidates->begin(), candidates->end(), false_positive), candidates->end());
	EXPECT_FALSE(compatible(gapped, rules[false_positive].filter));

	// An unrestricted terminal fallback before hosts must not be reordered away.
	rules.insert(rules.begin(), rule_t(nullptr, common::globalBase::tFlow(eFlowType::drop), ids_t{77}, true));
	const dispatcher_index_t terminal_index(rules);
	expect_same_dispatcher(rules, terminal_index, destination_filter(destinations({"10.0.0.7"})));
	const auto terminal = evaluate_dispatcher(rules, nullptr);
	ASSERT_EQ(terminal.size(), 1);
	EXPECT_THAT(terminal.front().ids, ::testing::ElementsAre(900, 77));
}

TEST(ACLUnwind, DispatcherCandidateShape)
{
	const size_t host_count = 1024;
	const auto rules = dispatcher_fixture(host_count);
	const auto fallbacks = rules.size() - host_count * RULES_PER_HOST;
	const dispatcher_index_t index(rules);
	for (unsigned i = 0; i < 48; ++i)
	{
		ref_t<filter_network_t> dst = new filter_network_t;
		dst->networks.emplace_back(4, 0x0a000000 + i * 17, uint32_t(-1));
		const auto query = destination_filter(dst, new filter_id_t(0));
		const auto candidates = index.candidates(query);
		ASSERT_TRUE(candidates);
		EXPECT_LE(candidates->size(), PROTOCOLS.size() + fallbacks); // One IPv4 host plus ordered fallbacks.
		EXPECT_TRUE(std::is_sorted(candidates->begin(), candidates->end()));
		EXPECT_EQ(std::adjacent_find(candidates->begin(), candidates->end()), candidates->end());
		if (i == 0)
		{
			expect_same_dispatcher(rules, index, query);
		}
	}
	const auto output = index.candidates(destination_filter(nullptr, new filter_id_t(1)));
	ASSERT_TRUE(output);
	ASSERT_EQ(output->size(), fallbacks);
	for (const auto ordinal : *output)
	{
		EXPECT_TRUE(ordinal < WILDCARD_RULES || ordinal >= first_host_rule(host_count));
	}
	EXPECT_FALSE(index.candidates(destination_filter(destinations({"0.0.0.0/0", "::/0"}), new filter_id_t(0))));

	// No fallbacks and no matching hosts is different from a full scan.
	std::vector<rule_t> hosts;
	add_dispatcher_rule(hosts, destination_filter(destinations({"10.0.0.1"}), new filter_id_t(0)));
	const dispatcher_index_t host_index(hosts);
	const auto none = host_index.candidates(destination_filter(destinations({"192.0.2.1"})));
	ASSERT_TRUE(none);
	EXPECT_TRUE(none->empty());
}

TEST(ACLUnwind, NestedViaLogKeepstateMetadata)
{
	auto fw = make_default_acl(R"IPFW(
add 10 skipto :IN ip from any to any in
add 20 allow ip from any to any out
:IN
add 30 skipto :VIP tcp from any to 10.0.0.7 via port0
add 40 deny ip from any to any
:VIP
add 50 skipto :ALLOW ip from any to any
:ALLOW
add 70 allow log ip from any to any keep-state
)IPFW");
	fw.nextModuleRules.clear();
	for (unsigned i = 0; i < 8; ++i)
	{
		common::globalBase::tFlow flow(eFlowType::route);
		flow.data.atomic = 42 + i;
		const auto destination = common::ipv4_prefix_t(i == 0 ? "10.0.0.7/32" : "192.0.2." + std::to_string(i) + "/32");
		fw.nextModuleRules.emplace_back(
		        controlplane::base::acl_rule_network_ipv4_t({common::ipv4_prefix_t("0.0.0.0/0")}, {destination}),
		        controlplane::base::acl_rule_transport_tcp_t(common::range_t{0, 65535}, common::range_t{80, 80}),
		        flow);
	}
	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	result_t result;
	const auto rules = unwind_used_rules(acls, {{1, {{false, "port0"}, {true, "port0"}, {true, "port1"}}}}, nullptr, result);
	ASSERT_EQ(rules.size(), 5);
	EXPECT_THAT(result.ids_map, ::testing::ElementsAre(ids_t{}, ids_t{2}, ids_t{1, 3, 5, 6}, ids_t{1, 4}));
	EXPECT_EQ(result.in_iface_map, (std::map<std::string, tAclId>{{"port0", 2}, {"port1", 3}}));
	EXPECT_EQ(result.out_iface_map, (std::map<std::string, tAclId>{{"port0", 1}}));
	EXPECT_EQ(result.acl_map, (std::map<tAclId, std::set<tAclId>>{{1, {1, 2, 3}}}));
	std::map<std::pair<int, ids_t>, std::vector<common::globalBase::tFlow>> flows;
	for (const auto& rule : rules)
	{
		ASSERT_TRUE(rule.filter);
		ASSERT_TRUE(rule.filter->acl_id);
		const auto& flow = std::get<common::globalBase::tFlow>(rule.action);
		flows[{rule.filter->acl_id->val, rule.ids}].push_back(flow);
		if (rule.ids == ids_t({1, 3, 5, 6}))
		{
			EXPECT_EQ(rule.filter->acl_id->val, 2);
			EXPECT_EQ(rule.filter->dir->val, 0);
			EXPECT_TRUE(rule.log);
			EXPECT_TRUE(rule.filter->keepstate);
			EXPECT_EQ(unsigned(flow.counter_id), 2);
			EXPECT_EQ(unsigned(flow.flags), 3);
		}
		else
		{
			EXPECT_FALSE(rule.log);
			EXPECT_EQ(unsigned(flow.flags), 0);
			EXPECT_EQ(unsigned(flow.counter_id), rule.ids == ids_t({2}) ? 1 : 3);
			EXPECT_EQ(rule.filter->dir->val, rule.ids == ids_t({2}) ? 1 : 0);
		}
	}
	const auto& allowed = flows[{2, ids_t{1, 3, 5, 6}}];
	ASSERT_EQ(allowed.size(), 2);
	EXPECT_EQ(allowed[0].type, eFlowType::route);
	EXPECT_EQ(allowed[0].data.atomic, 42);
	EXPECT_EQ(allowed[1].type, eFlowType::drop);
	const auto& egress = flows[{1, ids_t{2}}];
	ASSERT_EQ(egress.size(), 1);
	EXPECT_EQ(egress[0].type, eFlowType::logicalPort_egress);
	ASSERT_EQ(flows[std::make_pair(2, ids_t{1, 4})].size(), 1);
	ASSERT_EQ(flows[std::make_pair(3, ids_t{1, 4})].size(), 1);
	ASSERT_EQ(result.dispatcher.size(), 10);
	EXPECT_EQ(std::get<0>(result.dispatcher.front()), FW_DISPATCHER_START_ID);
	EXPECT_EQ(std::get<1>(result.dispatcher.front()), "flow route(42) src-addr 0.0.0.0 dst-addr 10.0.0.7/255.255.255.255 proto 6 src-port 0-65535 dst-port 80 in");
	EXPECT_EQ(std::get<1>(result.dispatcher[8]), "deny in");
	EXPECT_EQ(std::get<1>(result.dispatcher[9]), "flow logicalPort_egress(0) out");
	EXPECT_EQ(std::get<0>(result.rules.at(70).front()), 6);
	EXPECT_EQ(std::get<2>(result.rules.at(70).front()), "allow log ip from any to any keep-state");
}

} // namespace
