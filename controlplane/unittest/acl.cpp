#include <gmock/gmock-matchers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "../acl.h"
#include "common/actions.h"

namespace
{

using common::ipv4_address_t;
using common::globalBase::eFlowType;
using controlplane::base::acl_t;

auto make_default_acl(const std::string& rules, tAclId aclId = 1) -> acl_t
{
	acl_t acl;
	common::globalBase::tFlow flow{};
	flow.type = eFlowType::route;

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

// Custom matcher to check if a variant holds a specific type
template<typename T>
class HoldsAlternativeMatcher : public ::testing::MatcherInterface<const common::RawAction&>
{
public:
	bool MatchAndExplain(const common::RawAction& v, ::testing::MatchResultListener* listener) const override
	{
		return std::holds_alternative<T>(v);
	}

	void DescribeTo(std::ostream* os) const override
	{
		*os << "holds alternative of type " << typeid(T).name();
	}
};

template<typename T>
::testing::Matcher<const common::RawAction&> HoldsAlternative()
{
	return ::testing::MakeMatcher(new HoldsAlternativeMatcher<T>());
}

::testing::Matcher<const common::RawAction&> IsCheckStateAction()
{
	return HoldsAlternative<common::CheckStateAction>();
}

::testing::Matcher<const common::RawAction&> IsFlowAction()
{
	return HoldsAlternative<common::FlowAction>();
}

::testing::Matcher<const common::RawAction&> IsDumpAction()
{
	return HoldsAlternative<common::DumpAction>();
}

class ACL : public ::testing::Test
{
protected:
	acl::result_t result;

	// Helper function to compile the ACL with the interface map
	void compile_acl(const std::string& acl_rules, const acl::iface_map_t& iface_map = {{1, {{true, "vlan1"}}}})
	{
		auto fw = make_default_acl(acl_rules);
		std::map<std::string, acl_t> acls{{"acl0", std::move(fw)}};

		acl::compile(acls, iface_map, result);

		validate_paths();
	}

	// Helper function to visit a specific group based on its index
	template<typename Func>
	void visit_action_group(size_t group_index, Func&& func)
	{
		ASSERT_LT(group_index, result.acl_total_table.size()) << "Group index out of range.";
		auto total_table_value = std::get<1>(result.acl_total_table[group_index]);
		const auto& value = result.acl_values[total_table_value];

		std::visit(std::forward<Func>(func), value);
	}

	// Helper function to visit actions and apply the provided lambda to all action groups
	template<typename Func>
	void visit_actions(Func&& func)
	{
		for (size_t group_index = 0; group_index < result.acl_total_table.size(); ++group_index)
		{
			visit_action_group(group_index, std::forward<Func>(func));
		}
	}

	template<typename T>
	static constexpr bool is_with_check_state()
	{
		return std::is_same_v<std::decay_t<T>, common::BaseActions<common::ActionsPath::WithCheckState>>;
	}

	void validate_paths()
	{
		visit_actions([&](const auto& actions) {
			// Default path should always end with a FlowAction
			EXPECT_THAT(actions.default_path_last_raw_action(), IsFlowAction());

			if constexpr (is_with_check_state<decltype(actions)>())
			{
				// Check-state path should always end with CheckStateAction
				EXPECT_THAT(actions.check_state_path_last_raw_action(), IsCheckStateAction());
			}
		});
	}
};

class ACLWithUnwind : public ACL
{
protected:
	acl::unwind_result unwind_result;

	void unwind_and_compile_acl(const std::string& acl_rules, const acl::iface_map_t& iface_map = {{1, {{true, "vlan1"}}}})
	{
		auto fw = make_default_acl(acl_rules);
		std::map<std::string, acl_t> acls{{"acl0", std::move(fw)}};

		unwind_result = acl::unwind(acls, iface_map, {}, {}, {}, {}, {}, {}, {}, {}, {}, {});

		acl::compile(acls, iface_map, result);
	}
};

TEST_F(ACL, 001_Basic)
{
	compile_acl(R"IPFW(
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
}

TEST_F(ACL, 002_IPv4Only)
{
	compile_acl(R"IPFW(
:BEGIN
add skipto :IN ip from any to any in

:IN
add allow tcp from { 1.2.3.4 } to any dst-port 80
add deny ip from any to any
)IPFW");
}

TEST_F(ACL, 003_Over500)
{
	compile_acl(generate_firewall_conf(500));
}

TEST_F(ACL, 004_Over1000)
{
	compile_acl(generate_firewall_conf(1000));
}

TEST_F(ACL, 005_Over4000)
{
	compile_acl(generate_firewall_conf(4000));
}

TEST_F(ACL, 006_Counters)
{
	compile_acl(R"IPFW(
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

	visit_actions([&](const auto& actions) {
		EXPECT_THAT(actions.get_flow().counter_id, ::testing::Ge(1));
		EXPECT_THAT(actions.get_flow().counter_id, ::testing::Lt(5));
	});

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 5);

	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1, 2, 5));
	EXPECT_THAT(ids_map[2], ::testing::ElementsAre(1, 2, 7));
	EXPECT_THAT(ids_map[3], ::testing::ElementsAre(1, 3, 7));
	EXPECT_THAT(ids_map[4], ::testing::ElementsAre(1, 4));
}

TEST_F(ACL, 007_OrderDeny)
{
	compile_acl(R"IPFW(
:BEGIN
add 1 deny ip from any to any in
add 2 allow ip from { 1.2.3.4 } to any in
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 1);

	visit_actions([&](const auto& actions) {
		EXPECT_EQ(eFlowType::drop, actions.get_flow().type);
	});

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 2);
	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
}

TEST_F(ACL, 008_OrderAllow)
{
	compile_acl(R"IPFW(
:BEGIN
add 1 allow ip from { 1.2.3.4 } to any in
add 2 deny ip from any to any in
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 2);

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 3);

	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
	EXPECT_THAT(ids_map[2], ::testing::ElementsAre(2));
}

TEST_F(ACL, 010_Via)
{
	compile_acl(R"IPFW(
:BEGIN
add 1 allow ip from { 1.2.3.4 } to any in via port0
add 2 deny ip from any to any in
)IPFW",
	            {{1, {{true, "port0"}, {true, "port1"}}}});

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

TEST_F(ACL, 011_ViaOut)
{
	compile_acl(R"IPFW(
:BEGIN
add allow ip from { 1.2.3.4 } to any out via port0 // id 1
add allow ip from { 1.2.3.5 } to any out via port1 // id 2
add deny ip from any to any out // id 3
)IPFW",
	            {{1, {{false, "port0"}, {false, "port1"}, {false, "port2"}, {false, "port3"}}}});

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

// stringify a tuple
template<typename Tuple>
std::string stringify(Tuple&& v)
{
	return std::apply([](auto&&... e) { return (((e ? *e : "any") + "|") + ...); },
	                  std::forward<Tuple>(v));
}

TEST_F(ACLWithUnwind, 012_Lookup)
{
	unwind_and_compile_acl(R"IPFW(
:BEGIN
add skipto :ALL ip from any to any // id 1

:ALL
add allow ip from { 1.2.3.4 } to any out via port0 // id 2
add allow log ip from { 1.2.3.5 } to any out via port1 // id 3
add deny ip from any to any out // id 4
add allow ip from any to any in // id 5
)IPFW",
	                       {{1, {{false, "port0"}, {false, "port1"}, {false, "port2"}, {false, "port3"}, {true, "port0"}}}});

	ASSERT_EQ(unwind_result.size(), 6);

	std::set<std::string> expect = {"port2 port3 |1|any|any|any|any|any|any|any|false|drop(0)|1, 4|false|",
	                                "port0 |1|1.2.3.4/255.255.255.255|any|any|any|any|any|any|false|logicalPort_egress(0)|1, 2|false|",
	                                "port0 |1|any|any|any|any|any|any|any|false|drop(0)|1, 4|false|",
	                                "port0 |0|any|any|any|any|any|any|any|false|route(0)|1, 5|false|",
	                                "port1 |1|1.2.3.5/255.255.255.255|any|any|any|any|any|any|false|logicalPort_egress(0)|1, 3|true|",
	                                "port1 |1|any|any|any|any|any|any|any|false|drop(0)|1, 4|false|"};

	for (const auto& r : unwind_result)
	{
		auto str = stringify(r);

		std::cout << str << std::endl;
		EXPECT_THAT(expect.count(str), 1) << "No matching string for " << str;
	}
}

TEST_F(ACLWithUnwind, 013_DefaultAction)
{
	unwind_and_compile_acl(R"IPFW(
:BEGIN
add 1 allow icmp from { 1.2.3.4 } to any in
)IPFW",
	                       {{1, {{true, "vlan1"}, {false, "vlan1"}}}});

	ASSERT_EQ(unwind_result.size(), 3);
	ASSERT_EQ(result.acl_total_table.size(), 4);

	EXPECT_EQ("vlan1 |0|1.2.3.4/255.255.255.255|any|any|1|any|any|any|false|route(0)|1|false|", stringify(unwind_result[0]));
	EXPECT_EQ("vlan1 |0|any|any|any|any|any|any|any|false|route(0)||false|", stringify(unwind_result[1]));
	EXPECT_EQ("vlan1 |1|any|any|any|any|any|any|any|false|logicalPort_egress(0)||false|", stringify(unwind_result[2]));

	auto& ids_map = result.ids_map;
	ASSERT_EQ(ids_map.size(), 2);

	EXPECT_THAT(ids_map[0], ::testing::ElementsAre());
	EXPECT_THAT(ids_map[1], ::testing::ElementsAre(1));
}

TEST_F(ACLWithUnwind, 014_Log)
{
	unwind_and_compile_acl(R"IPFW(
:BEGIN
add 100 allow log ip from { 1.2.3.4 } to any in via port0
add 200 deny log ip from any to any in
add 300 deny ip from any to any
)IPFW",
	                       {{1, {{true, "port0"}, {true, "port1"}}}});

	ASSERT_EQ(unwind_result.size(), 3);
	ASSERT_EQ(result.acl_total_table.size(), 4);

	EXPECT_EQ("port1 |0|any|any|any|any|any|any|any|false|drop(0)|2|true|", stringify(unwind_result[0]));
	EXPECT_EQ("port0 |0|1.2.3.4/255.255.255.255|any|any|any|any|any|any|false|route(0)|1|true|", stringify(unwind_result[1]));
	EXPECT_EQ("port0 |0|any|any|any|any|any|any|any|false|drop(0)|2|true|", stringify(unwind_result[2]));

	visit_actions([&](const auto& actions) {
		EXPECT_EQ(actions.get_flow().flags, static_cast<int>(common::globalBase::eFlowFlags::log));
	});

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
	EXPECT_EQ("allow log ip from { 1.2.3.4 } to any in via port0", std::get<2>(result.rules[100].front()));
	EXPECT_EQ("deny log ip from any to any in", std::get<2>(result.rules[200].front()));
	EXPECT_EQ("deny ip from any to any", std::get<2>(result.rules[300].front()));
}

TEST_F(ACLWithUnwind, 015_GappedMask)
{
	unwind_and_compile_acl(R"IPFW(
:BEGIN
add 100 allow proto tcp dst-addr 4242@2abc:123:c00::/40
add 200 allow proto tcp dst-addr fc00/23@2abc:123:c00::/40
add 300 allow proto tcp dst-addr 1234567@2abc:123:c00::/40
)IPFW");

	ASSERT_EQ(unwind_result.size(), 4);

	// check that parser correctly expands gapped mask in rules -> compare with generated text
	EXPECT_EQ("allow dst-addr 2abc:123:c00::4242:0:0/ffff:ffff:ff00:0:ffff:ffff:: proto 6", std::get<1>(result.rules[100].front()));
	EXPECT_EQ("allow dst-addr 2abc:123:c00::fc00:0:0/ffff:ffff:ff00:0:ffff:fe00:: proto 6", std::get<1>(result.rules[200].front()));
	EXPECT_EQ("allow dst-addr 2abc:123:c00:0:123:4567::/ffff:ffff:ff00:0:ffff:ffff:: proto 6", std::get<1>(result.rules[300].front()));
}

TEST_F(ACLWithUnwind, 016_TcpFlags)
{
	unwind_and_compile_acl(R"IPFW(
:BEGIN
add 100 deny tcp from any to any setup
add 150 deny tcp from any to any tcpflags syn,!ack // the same as setup
add 200 deny tcp from any to any tcpflags fin,psh,urg
add 300 deny tcp from any to any tcpflags !syn,!fin,!ack,!psh,!rst,!urg
add 400 allow tcp from any to any tcpflags rst
add 500 allow tcp from any to any established
)IPFW");

	ASSERT_EQ(unwind_result.size(), 7);
	// check that parser correctly expands tcpflags and then filter correctly formats them
	EXPECT_EQ("deny proto 6 setup", std::get<1>(result.rules[100].front()));
	EXPECT_EQ("deny proto 6 setup", std::get<1>(result.rules[150].front()));
	EXPECT_EQ("deny proto 6 tcpflags fin,psh,urg", std::get<1>(result.rules[200].front()));
	EXPECT_EQ("deny proto 6 tcpflags !fin,!syn,!rst,!psh,!ack,!urg", std::get<1>(result.rules[300].front()));
	EXPECT_EQ("allow proto 6 tcpflags rst", std::get<1>(result.rules[400].front()));
	EXPECT_EQ("allow proto 6 etsablished", std::get<1>(result.rules[500].front()));
}

TEST_F(ACLWithUnwind, 017_IcmpTypes)
{
	unwind_and_compile_acl(R"IPFW(
:BEGIN
add 100 allow icmp from any to any icmptypes 0,8,3,11,12
# parser automatically inserts ICMP or ICMPv6 protocol
# when it is not specified
add 200 deny ip from any to any icmptypes 1,2,3,9,10,13
add 300 allow ip from any to any icmp6types 133,134,135,136
)IPFW");

	ASSERT_EQ(unwind_result.size(), 4);
	// check that parser correctly expands icmptypes and then filter correctly formats them
	EXPECT_EQ("allow proto 1 icmptypes 0,3,8,11,12", std::get<1>(result.rules[100].front()));
	EXPECT_EQ("deny proto 1 icmptypes 1,2,3,9,10,13", std::get<1>(result.rules[200].front()));
	EXPECT_EQ("allow proto 58 icmp6types 133,134,135,136", std::get<1>(result.rules[300].front()));
}

TEST_F(ACLWithUnwind, 018_EmptyDst)
{
	unwind_and_compile_acl(R"IPFW(
:BEGIN
add 100 allow icmp from any to unknown.hostname.tld icmptypes 0,8
add 200 deny ip from any to any
)IPFW");

	ASSERT_EQ(unwind_result.size(), 1);
	// we expect that after validation rule 100 will be omitted and only one rule will remain
	EXPECT_EQ("deny", std::get<1>(result.rules[200].front()));
}

TEST_F(ACL, 019_CheckStateBasic)
{
	compile_acl(R"IPFW(
:BEGIN
add 100 check-state
add 200 allow ip from { 1.2.3.4 } to any
add 300 deny ip from any to any
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 2);
}

TEST_F(ACL, 020_ManyCheckStates)
{
	compile_acl(R"IPFW(
:BEGIN
add 100 check-state
add 200 dump ring1 ip from { 1.2.3.4 } to any
add 300 check-state
add 400 deny ip from any to any
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 2);

	// We're interested in second group, i.e the group where src ip is { 1.2.3.4 }
	visit_action_group(1, [&](const auto& actions) {
		if constexpr (is_with_check_state<decltype(actions)>())
		{
			// Check that the default path includes the actions after the first and second check-states
			EXPECT_THAT(actions.default_path_size(), 2);
			EXPECT_THAT(actions.default_path_raw_action(0), IsDumpAction());
			EXPECT_THAT(actions.default_path_raw_action(1), IsFlowAction());
		}
	});
}

TEST_F(ACL, 021_CheckStateComplex)
{
	compile_acl(R"IPFW(
:BEGIN
add 100 dump ring1 ip from { 1.2.3.4 } to any
add 200 check-state
add 300 dump ring2 ip from { 1.2.3.4 } to any
add 500 check-state
add 500 deny ip from any to any
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 2);

	// We're interested in second group, i.e the group where src ip is { 1.2.3.4 }
	visit_action_group(1, [&](const auto& actions) {
		if constexpr (is_with_check_state<decltype(actions)>())
		{
			// Check that the default path includes actions before and after the check-state
			EXPECT_THAT(actions.default_path_size(), 3);
			EXPECT_THAT(actions.default_path_raw_action(0), IsDumpAction());
			EXPECT_THAT(actions.default_path_raw_action(1), IsDumpAction());
			EXPECT_THAT(actions.default_path_raw_action(2), IsFlowAction());

			// Check that the check-state path includes actions up to and including the check-state action
			EXPECT_THAT(actions.check_state_path_size(), 2);
			EXPECT_THAT(actions.check_state_path_raw_action(0), IsDumpAction());
			EXPECT_THAT(actions.check_state_path_raw_action(1), IsCheckStateAction());
		}
	});
}

TEST_F(ACL, KeepState_Basic)
{
	compile_acl(R"IPFW(
:BEGIN
add allow ip from any to any keep-state
add deny ip from any to any
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 1);
}

TEST_F(ACL, KeepState_MultipleRules)
{
	compile_acl(R"IPFW(
:BEGIN
add allow ip from { 1.2.3.4 } to any keep-state
add allow ip from any to any 22 keep-state
add deny ip from any to any
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 2);
}

TEST_F(ACL, KeepState_WithSkipTo)
{
	compile_acl(R"IPFW(
:BEGIN
add skipto :IN ip from { 1.2.3.4 } to any in
add deny ip from any to any

:IN
add allow ip from any to any keep-state
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 2);
}

TEST_F(ACL, StateTimeout_Basic)
{
	compile_acl(R"IPFW(
:BEGIN
add state-timeout 5000 ip from any to any
add allow ip from any to any keep-state
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 1);

	visit_actions([&](const auto& actions) {
		const auto& flow_action = std::get<common::FlowAction>(actions.default_path_last_raw_action());
		EXPECT_EQ(flow_action.timeout, 5000);
	});
}

TEST_F(ACL, StateTimeout_RestrictiveSubset)
{
	compile_acl(R"IPFW(
:BEGIN
add state-timeout 8000 ip from any to any
add state-timeout 3000 ip from 192.168.1.0/24 to any
add allow ip from any to any keep-state
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 2);

	// First group, ip not in 192.168.1.0/24
	visit_action_group(0, [&](const auto& actions) {
		const auto& flow_action = std::get<common::FlowAction>(actions.default_path_last_raw_action());
		EXPECT_EQ(flow_action.timeout, 8000);
	});

	// Second group, ip is in 192.168.1.0/24
	visit_action_group(1, [&](const auto& actions) {
		const auto& flow_action = std::get<common::FlowAction>(actions.default_path_last_raw_action());
		EXPECT_EQ(flow_action.timeout, 3000); // Verify that the timeout for 192.168.1.0/24 is 3000
	});
}

TEST_F(ACL, StateTimeout_NoTimeout)
{
	compile_acl(R"IPFW(
:BEGIN
add allow ip from any to any
)IPFW");

	ASSERT_EQ(result.acl_total_table.size(), 1);

	visit_actions([&](const auto& actions) {
		const auto& flow_action = std::get<common::FlowAction>(actions.default_path_last_raw_action());
		// Check that by default timeout in flow_action is std::nullopt
		EXPECT_EQ(flow_action.timeout, std::nullopt);
	});
}

} // namespace
