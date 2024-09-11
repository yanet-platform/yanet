#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "../acl.h"

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
		std::visit([&](const auto& actions) { EXPECT_THAT(actions.get_flow().counter_id, ::testing::Ge(1)); }, value);
		std::visit([&](const auto& actions) { EXPECT_THAT(actions.get_flow().counter_id, ::testing::Lt(5)); }, value);
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
		std::visit([&](const auto& actions) {
			EXPECT_THAT(actions.get_flow().type, ::testing::Eq(common::globalBase::eFlowType::drop));
		},
		           value);
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
		std::visit([&](const auto& actions) {
			EXPECT_THAT(actions.get_flow().flags, ::testing::Eq((uint8_t)common::globalBase::eFlowFlags::log));
		},
		           result.acl_values[total_table_value]);
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

TEST(ACL, 019_CheckStateBasic)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 check-state
add 200 allow ip from { 1.2.3.4 } to any
add 300 deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 2);

	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;

		const auto& value = result.acl_values[total_table_value];
		std::visit([&](const auto& actions) {
			if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<common::ActionsPath::WithCheckState>>)
			{
				// Check that the regular path does not include the check-state action
				EXPECT_THAT(actions.get_actions().size(), 1);
				EXPECT_FALSE(std::holds_alternative<common::CheckStateAction>(actions.get_actions()[0].raw_action));

				// Check that the check-state path includes the check-state action
				EXPECT_THAT(actions.get_check_state_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
			}
		},
		           value);
	}
}

TEST(ACL, 020_ManyCheckStates)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 check-state
add 200 dump ring1 ip from { 1.2.3.4 } to any
add 300 check-state
add 400 deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 2);

	// We're interested in second group, i.e the group where src ip is { 1.2.3.4 }
	auto total_table_value = std::get<1>(result.acl_total_table[1]);

	const auto& value = result.acl_values[total_table_value];
	std::visit([&](const auto& actions) {
		if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<common::ActionsPath::WithCheckState>>)
		{
			// Check that the regular path includes the actions after the first and second check-states
			EXPECT_THAT(actions.get_actions().size(), 2);
			EXPECT_TRUE(std::holds_alternative<common::DumpAction>(actions.get_actions()[0].raw_action));
			EXPECT_TRUE(std::holds_alternative<common::FlowAction>(actions.get_actions()[1].raw_action));

			// Check that the check-state path includes the first check-state action and no other actions
			EXPECT_THAT(actions.get_check_state_actions().size(), 1);
			EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
		}
	},
	           value);
}

TEST(ACL, 021_CheckStateComplex)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add 100 dump ring1 ip from { 1.2.3.4 } to any
add 200 check-state
add 300 dump ring2 ip from { 1.2.3.4 } to any
add 500 check-state
add 500 deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 2);

	// We're interested in second group, i.e the group where src ip is { 1.2.3.4 }
	auto total_table_value = std::get<1>(result.acl_total_table[1]);

	const auto& value = result.acl_values[total_table_value];
	std::visit([&](const auto& actions) {
		if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<common::ActionsPath::WithCheckState>>)
		{
			// Check that the regular path includes actions before and after the check-state
			EXPECT_THAT(actions.get_actions().size(), 3);
			EXPECT_TRUE(std::holds_alternative<common::DumpAction>(actions.get_actions()[0].raw_action));
			EXPECT_TRUE(std::holds_alternative<common::DumpAction>(actions.get_actions()[1].raw_action));
			EXPECT_TRUE(std::holds_alternative<common::FlowAction>(actions.get_actions()[2].raw_action));

			// Check that the check-state path includes actions up to and including the check-state action
			EXPECT_THAT(actions.get_check_state_actions().size(), 2);
			EXPECT_TRUE(std::holds_alternative<common::DumpAction>(actions.get_check_state_actions()[0].raw_action));
			EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions()[1].raw_action));
		}
	},
	           value);
}

TEST(ACL, KeepState_Basic)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add allow ip from any to any keep-state
add deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 1);

	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;

		const auto& value = result.acl_values[total_table_value];
		std::visit([&](const auto& actions) {
			if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<common::ActionsPath::WithCheckState>>)
			{
				// Check that the regular path includes the allow action
				EXPECT_THAT(actions.get_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::FlowAction>(actions.get_actions()[0].raw_action));

				// Check that the check-state path includes the check-state action
				EXPECT_THAT(actions.get_check_state_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
			}
		},
		           value);
	}
}

TEST(ACL, KeepState_MultipleRules)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add allow ip from { 1.2.3.4 } to any keep-state
add allow ip from any to any 22 keep-state
add deny ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 2);

	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;

		const auto& value = result.acl_values[total_table_value];
		std::visit([&](const auto& actions) {
			if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<common::ActionsPath::WithCheckState>>)
			{
				// Check that the regular path includes the allow action
				EXPECT_THAT(actions.get_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::FlowAction>(actions.get_actions()[0].raw_action));

				// Check that the check-state path includes the check-state action
				EXPECT_THAT(actions.get_check_state_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
			}
		},
		           value);
	}
}

TEST(ACL, KeepState_WithSkipTo)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add skipto :IN ip from { 1.2.3.4 } to any in
add deny ip from any to any

:IN
add allow ip from any to any keep-state
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 2);

	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;

		const auto& value = result.acl_values[total_table_value];
		std::visit([&](const auto& actions) {
			if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<common::ActionsPath::WithCheckState>>)
			{
				// Check that the regular path includes the allow action
				EXPECT_THAT(actions.get_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::FlowAction>(actions.get_actions()[0].raw_action));

				// Check that the check-state path includes the check-state action
				EXPECT_THAT(actions.get_check_state_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
			}
		},
		           value);
	}
}

TEST(ACL, StateTimeout_Basic)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add state-timeout 5000 ip from any to any
add allow ip from any to any keep-state
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 1);

	for (const auto& [total_table_key, total_table_value] : result.acl_total_table)
	{
		(void)total_table_key;

		const auto& value = result.acl_values[total_table_value];
		std::visit([&](const auto& actions) {
			if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<true>>)
			{
				// Check that the regular path includes the allow action with the correct timeout
				EXPECT_THAT(actions.get_actions().size(), 1);
				const auto& flow_action = std::get<common::FlowAction>(actions.get_actions()[0].raw_action);
				EXPECT_EQ(flow_action.timeout, 5000);

				// Check that the check-state path includes only check-state action
				EXPECT_THAT(actions.get_check_state_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
			}
		},
		           value);
	}
}

TEST(ACL, StateTimeout_RestrictiveSubset)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add state-timeout 8000 ip from any to any
add state-timeout 3000 ip from 192.168.1.0/24 to any
add allow ip from any to any keep-state
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 2);

	{
		// First group, ip not in 192.168.1.0/24
		auto total_table_value = std::get<1>(result.acl_total_table[0]);
		const auto& value = result.acl_values[total_table_value];

		std::visit([&](const auto& actions) {
			if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<true>>)
			{
				// Check that the regular path includes the allow action with the correct timeout
				EXPECT_THAT(actions.get_actions().size(), 1);
				const auto& flow_action = std::get<common::FlowAction>(actions.get_actions()[0].raw_action);
				EXPECT_EQ(flow_action.timeout, 8000);

				// Check that the check-state path includes only check-state action
				EXPECT_THAT(actions.get_check_state_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
			}
		},
		           value);
	}
	{
		// Second group, ip is in 192.168.1.0/24
		auto total_table_value = std::get<1>(result.acl_total_table[1]);
		const auto& value = result.acl_values[total_table_value];

		std::visit([&](const auto& actions) {
			if constexpr (std::is_same_v<std::decay_t<decltype(actions)>, common::BaseActions<true>>)
			{
				// Check that the regular path includes the allow action with the correct timeout
				EXPECT_THAT(actions.get_actions().size(), 1);

				const auto& flow_action = std::get<common::FlowAction>(actions.get_actions()[0].raw_action);
				EXPECT_EQ(flow_action.timeout, 3000); // Verify that the timeout for 192.168.1.0/24 is 3000

				// Check that the check-state path includes only check-state action
				EXPECT_THAT(actions.get_check_state_actions().size(), 1);
				EXPECT_TRUE(std::holds_alternative<common::CheckStateAction>(actions.get_check_state_actions().back().raw_action));
			}
		},
		           value);
	}
}

TEST(ACL, StateTimeout_NoTimeout)
{
	auto fw = make_default_acl(R"IPFW(
:BEGIN
add allow ip from any to any
)IPFW");

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	acl::compile(acls, {{1, {{true, "vlan1"}}}}, result);

	ASSERT_EQ(result.acl_total_table.size(), 1);

	auto total_table_value = std::get<1>(result.acl_total_table[0]);
	const auto& value = result.acl_values[total_table_value];

	const auto& last_action = std::visit([&](const auto& actions) { return actions.get_last(); }, value);
	const auto& flow_action = std::get<common::FlowAction>(last_action.raw_action);
	// Check that by default timeout in flow_action is std::nullopt
	EXPECT_EQ(flow_action.timeout, std::nullopt);
}

} // namespace
