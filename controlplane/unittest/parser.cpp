#include <gtest/gtest.h>

#include "libfwparser/fw_parser.h"

namespace
{

auto parse_rules(const std::string& rules, bool validation = false)
{
	bool ret = false;

	ipfw::fw_config_t firewall;
	firewall.schedule_string(rules);
	ret = firewall.parse();
	if (ret && validation)
	{
		return firewall.validate();
	}
	return ret;
}

TEST(Parser, 001_Basic)
{
	const auto rules = R"IPFW(
add allow tcp from any to any 22
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 002_Sequence)
{
	const auto rules = R"IPFW(
add allow tcp from any to any 80,443
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 003_Range)
{
	const auto rules = R"IPFW(
add allow tcp from any to any 5000-65535
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 004_Multiline)
{
	const auto rules = R"IPFW(
add allow tcp from any to any 22
add allow tcp from any to any 80,443
add allow tcp from any to any 1000-1024
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 005_MultipleProtocols)
{
	const auto rules = R"IPFW(
add allow { tcp or udp } from any to any 5000-65535
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 006_MultipleTargets)
{
	const auto rules = R"IPFW(
add allow tcp from 127.0.0.1 to { 192.168.0.1 or 172.0.0.1/24 } 80
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 007_MultipleTargetsWithoutSpaces)
{
	const auto rules = R"IPFW(
add allow tcp from 127.0.0.1 to {192.168.0.1 or 172.0.0.1/24} 80
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 008_Macro)
{
	const auto rules = R"IPFW(
# Macros cache entries:
_ANETS_: 2123:ddcc::/32, 2123:ddcc:400::/48, 2891:df:c00::9119:0:0/ffff:ffff:ff00:0:ffff:ffff::
_BNETS_: 12.34.152.0/21, 23.45.160.0/21, 34.56.76.0/22, 2123:5678::/32, 45.56.82.0/23, 2000:d00:3::/48, 2000:d00:4::/48

add allow tcp from 127.0.0.1 to { _ANETS_ } 80
add allow tcp from { _BNETS_ } to { _ANETS_ } 80,443
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 009_Hostname)
{
	const auto rules = R"IPFW(
# DNS Cache entry
super-host.agu.buga.da.net 1.2.3.4,2222:3333:aaaa::b actual

add allow tcp from 127.0.0.1 to { super-host.agu.buga.da.net } 80
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 010_OutOption)
{
	const auto rules = R"IPFW(
add allow tcp from any to any 80 out
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 011_ViaOption)
{
	const auto rules = R"IPFW(
add allow tcp from any to any 80 out via vlan100500
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 012_IcmpTypesOption)
{
	const auto rules = R"IPFW(
add allow ip from any to any icmptype 11
add allow icmp from any to any icmptypes 0,8,3,11,12
add allow ip from any to any icmp6types 1,2,3,4,128,129,133,134,135,136
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 013_FragOption)
{
	const auto rules = R"IPFW(
add allow ip from any to any frag
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 014_SrcPortOption)
{
	const auto rules = R"IPFW(
_CNETS_: 12.34.56.128/29, 2123:bf:20:42::/64
_DNETS_: 71.72.225.0/29, 81.82.83.200/29
add allow tcp from me to { _CNETS_ or _DNETS_ } src-port 179
add allow tcp from any 179 to me
add allow udp from any src-port 53 to any
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 015_DstPortOption)
{
	const auto rules = R"IPFW(
_CNETS_: 12.34.56.128/29, 2123:bf:20:42::/64
_DNETS_: 71.72.225.0/29, 81.82.83.200/29

add allow udp from { _CNETS_ or _DNETS_ } to { _CNETS_ or _DNETS_ } dst-port 3784,4784
add allow tcp from any to any 80,443
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 016_DstPortOption)
{
	const auto rules = R"IPFW(
_CNETS_: 12.34.56.128/29, 2123:bf:20:42::/64
_DNETS_: 71.72.225.0/29, 81.82.83.200/29

# dst-port option is not allowed after src-statement
add allow udp from { _CNETS_ or _DNETS_ } dst-port 3784,4784 to { _CNETS_ or _DNETS_ }
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 017_RecordStateOption)
{
	const auto rules = R"IPFW(
add allow icmp from me to any icmptypes 8 out record-state
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 018_TcpFlagsOption)
{
	const auto rules = R"IPFW(
add allow tcp from { 11.22.33.160/28 or 12.123.123.96/28 } to { 111.222.240.0/22 or 222.111.192.0/19  } established
add skipto :JUMP tcp from any to any tcpflags syn,!ack
add deny tcp from any to any setup
add deny tcp from any to any tcpflags !syn,!fin,!ack,!psh,!rst,!urg
add deny tcp from any to any tcpflags fin,psh,urg
add allow tcp from any to any tcpflags rst
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 019_ProtoOption)
{
	const auto rules = R"IPFW(
# DNS cache
ho1.da.net 2abc:123:b011:1a1a:2b2b:3b3b:6d6d:faaa actual
ho2.da.net 11.222.123.93,2abc:123:abab:31::100 actual
ho3.da.net 11.222.123.91,2abc:123:abab:31::ffff actual

# Macros
_ENETS_: 1.12.192.0/18, 2abc:123::/32
_FNETS_: 2abc:123:abab:a0ff::/64, 2abc:123:abab:a0fd::/64, 2abc:123:abab:a0fc::/64
_MACRO1_: ho1.da.net, ho2.da.net, ho3.da.net
_MACRO2_: 3333:fff:d000::/44, 4444:123::/32, 4444:5555::/32
_MACRO3_: 5.6.123.128/29, 2abc:123:abab:a0fe::/64, 2abc:123:6666::/64

add allow ip from { _ENETS_ } to { _FNETS_ } proto ipencap in
add allow tag 653 ip4 from { 172.20.0.0/16 } to { _MACRO1_ } { proto tcp or proto icmp or proto udp }
add allow ip from { _MACRO3_ } to { _MACRO2_ } proto ipv6 out
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 020_IgnoredOptions)
{
	const auto rules = R"IPFW(
# just ignore antispoof, diverted, logamount, tag, tagged,
add allow tcp from 10.0.0.0/8 to 10.0.0.0/8 80 in antispoof
add 65534 allow ip from any to any diverted record-state
add deny log logamount 500 all from any to any
add allow tag 653 ip4 from { 10.0.0.0/8 } to me
add allow ip from any to any tagged 31000
add skipto :HELP ip from any to any not tagged 63
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 021_NamedPorts)
{
	const auto rules = R"IPFW(
_ENETS_: 1.12.192.0/18, 7777:ddd::/32
add allow udp from { _ENETS_ } bootpc,bootps to me bootps
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 022_OctalIPv4)
{
	const auto rules = R"IPFW(
# inet_pton() fails to parse octets in octal form
# but inet_aton() does it.
add allow tcp from 192.168.001.010 to any 80
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 023_IPv6)
{
	const auto rules = R"IPFW(
add allow tcp from ::/:: to any 80
add allow tcp from ::1 to any 80
add allow tcp from ::2:1 to any 80
add allow tcp from ::3:2:1 to any 80
add allow tcp from ::4:3:2:1 to any 80
add allow tcp from ::5:4:3:2:1 to any 80
add allow tcp from ::6:5:4:3:2:1 to any 80
add allow tcp from ::7:6:5:4:3:2:1 to any 80
add allow tcp from 8:7:6:5:4:3:2:1 to ::ffff:0.0.0.1 80
add allow udp from ::ffff/96 to any 53
add allow udp from me to { 7777:ddd:0:10::77.88.6.64 } out
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 024_Tables)
{
	const auto rules = R"IPFW(
# Implicit automatic table creation
table _MACROB_ add 5.6.123.144/29
table _MACROB_ add 1.12.200.24/30
table _MACROB_ add 1.12.203.64/31

# Explicit table creation
table _MCR_ create type iface
table _MCR_ add i123 :J1
table _MCR_ add i567 :J2

# Skipto via prefix tables
table _MACRO8_ add 1.12.192.0/18 :SK1
table _MACRO8_ add 66.77.88.160/27 :SK2
table _MACRO8_ add 77.88.99.0/25 :SK3

# Expand tables
add allow icmp from { table(_MACROB_) } to any
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 028_Comments)
{
	const auto rules = R"IPFW(
# comments, empty commens, commented rules, rule's comments
#
# add allow ip from any to any src-port 53 dst-port 20000-65535
_XNET_: 1.1.1.136/29, 2.2.2.192/26
add skipto :S1 ip from me to any // S1
add allow ip from any to { _XNET_ } // S
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 029_SkiptoBackwards)
{
	const auto rules = R"IPFW(
:BEGIN
add skipto :BEGIN ip from any to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 030_SkiptoBackwards)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 skipto 50 ip from any to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 031_LabelBetweenRules)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 allow ip from any to any
:SEC_IN
add 100 allow tcp from any to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 032_UnknownMacro)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 allow ip from { _ENETS_ } to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules, true));
}

TEST(Parser, 033_UnknownHostname)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 allow ip from { host9.true.false.da.net } to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules, true));
}

TEST(Parser, 034_UnknownHostnameInMacro)
{
	const auto rules = R"IPFW(
# macro has unknown hostname
_TESTING_HOSTS_: host9.true.false.da.net
:BEGIN
add 100 allow ip from { _TESTING_HOSTS_ } to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules, true));
}

TEST(Parser, 035_UnknownHostnameInMacro)
{
	const auto rules = R"IPFW(
# macro has unknown hostname, but it also has IPv4 network
_TESTING_HOSTS_: host9.true.false.da.net, 222.222.160.0/21
:BEGIN
add 100 allow ip from { _TESTING_HOSTS_ } to any
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 036_UnknownHostnameInMacro)
{
	const auto rules = R"IPFW(
# empty macro, but target source in rules still valid
_TESTING_HOSTS_: host9.true.false.da.net
:BEGIN
add 100 allow ip from { _TESTING_HOSTS_ or 222.222.160.0/21 } to any
add 200 allow tcp from { host10.da.net or 222.222.160.0/21 } to any
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 037_CompactFormat)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 allow proto tcp src-addr 222.222.160.0/21 in via if99
add 150 allow icmptypes 0,8
add 200 allow icmp6types 135,136
add 250 allow proto udp dst-port 53
add 300 deny
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 038_CompactFormatUnknownMacro)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 allow proto tcp src-addr _TESTING_HOSTS_ in via if99
)IPFW";
	EXPECT_FALSE(parse_rules(rules, true));
}

TEST(Parser, 039_CompactFormatUnknownHostname)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 allow proto tcp src-addr host9.true.false.da.net in via if99
)IPFW";
	EXPECT_FALSE(parse_rules(rules, true));
}

TEST(Parser, 040_M4EscapedHostname)
{
	const auto rules = R"IPFW(
# DNS Cache entries
host11.da.net 7777:ddd:c0e:123::abcd actual
unknown.da.net 1.2.3.4,7777:ddd:c03:777:0::fafa actual

# Macros
_MCRMCR_: host11.da.net

:BEGIN
add allow tcp from { _MCRMCR_ } to { `unknown.da.net' } 2020,2222

# Compact form
add allow proto tcp dst-addr `unknown.da.net' dst-port 2020,2222
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 041_UnknownLabel)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 skipto :SEC_IN ip from any to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules, true));
}

TEST(Parser, 042_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# Basic test for skipto tablearg via table(N)
table _SKIPTO_IN_ create type iface
table _SKIPTO_IN_ add if42 :SK1
table _SKIPTO_IN_ add if422 :SK2
table _SKIPTO_IN_ add uf4222 :SK3

:BEGIN
add skipto tablearg ip from any to any via table(_SKIPTO_IN_) in
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 043_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# table N has not been defined
:BEGIN
add skipto tablearg ip from any to any via table(_SKIPTO_IN_) in
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 044_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# table N has wrong type
table _SKIPTO_IN_ add 10.0.0.1/24
:BEGIN
add skipto tablearg ip from any to any via table(_SKIPTO_IN_) in
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 045_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# Basic test for skipto tablearg
table _S_PREFIX_ add 1.12.192.0/18 :J1
table _S_PREFIX_ add 80.80.80.160/27 :J2
table _S_PREFIX_ add 1.2.3.128/29 :J3
table _S_PREFIX_ add 1.2.3.160/27 :J3
table _S_PREFIX_ add 1.2.4.0/26 :J3

:BEGIN
add skipto tablearg ip from any to table(_S_PREFIX_)
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 046_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# table N has not been defined
:BEGIN
add skipto tablearg ip from any to table(_S_PREFIX_)
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 047_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# table N has wrong type
table _SKIPTO_IN_ create type iface
table _SKIPTO_IN_ add if2 :I1
table _SKIPTO_IN_ add if3 :I2
:BEGIN
add skipto tablearg ip from any to table(_SKIPTO_IN_)
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 048_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# several tables specified for tablearg (not supported yet)
table _S_PREFIX_ add 80.80.80.160/27 :J2
table _MACRO8_ add 77.88.99.128/29 :J3

:BEGIN
add skipto tablearg ip from table(_MACRO8_) to table(_S_PREFIX_)
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 049_ViaTable)
{
	const auto rules = R"IPFW(
# Basic test for via table
table _S_IFACES_ create type iface
table _S_IFACES_ add i101
table _S_IFACES_ add i102
table _S_IFACES_ add i103
table _S_IFACES_ add i104

:BEGIN
add allow ip from any to any via table(_S_IFACES_)
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 050_Prefixlen)
{
	const auto rules = R"IPFW(
# various prefix len for IPv4/IPv6 prefixes
:BEGIN
add allow ip from any to 10.0.0.1/0
add allow ip from any to 10.0.0.1/28
add allow ip from any to 10.0.0.1/32
add allow ip from any to fe80::1/0
add allow ip from any to fe80::1/8
add allow ip from any to fe80::1/32
add allow ip from any to fe80::1/64
add allow ip from any to fe80::1/128
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 051_Prefixlen)
{
	const auto rules = R"IPFW(
# bad prefixlen
:BEGIN
add allow ip from any to 10.0.0.1/128
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 052_Prefixlen)
{
	const auto rules = R"IPFW(
# bad prefixlen
:BEGIN
add allow ip from any to fe80::1/100500
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 053_SkiptoBackwards)
{
	const auto rules = R"IPFW(
:BEGIN
add 100 skipto 100 ip from any to any
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 054_NumericProtoOption)
{
	const auto rules = R"IPFW(
:BEGIN
add allow 17 from any to any
add allow proto 6
add allow ip from any to any proto 58
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 055_SkiptoTablearg)
{
	const auto rules = R"IPFW(
# One enty added without label. This is allowed, but it won't work,
# since unwind() will ignore this entry.
table _S_PREFIX_ create type addr
table _S_PREFIX_ add 1.12.192.0/18 :J1
table _S_PREFIX_ add 111.111.111.160/27 :J2
table _S_PREFIX_ add 77.88.99.0/26

:BEGIN
add skipto tablearg ip from any to table(_S_PREFIX_)
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 055_TableWithHostnames)
{
	const auto rules = R"IPFW(
# DNS Cache entry
host9.true.false.da.net 5.5.5.5,7777:ddd:c02:555:0:777:6543:2100 actual
hello.da.net 6.6.6.6,7777:ddd:b0b0:a1a1::ffff actual

table _S_PREFIX_ create type addr
table _S_PREFIX_ add host9.true.false.da.net :J1
table _S_PREFIX_ add hello.da.net

:BEGIN
add skipto tablearg ip from any to table(_S_PREFIX_)
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 056_UnknownHostnameInTable)
{
	const auto rules = R"IPFW(
# unknown hostname in table leads to empty dst addresses
table _S_PREFIX_ create type addr
table _S_PREFIX_ add hello.da.net

:BEGIN
add allow ip from any to { table(_S_PREFIX_) }
)IPFW";
	EXPECT_FALSE(parse_rules(rules, true));
}

TEST(Parser, 057_AnyOverridesEmptyDestination)
{
	const auto rules = R"IPFW(
# unknown hostname in table leads to empty dst addresses
table _S_PREFIX_ create type addr
table _S_PREFIX_ add hello.da.net

:BEGIN
add allow ip from any to { table(_S_PREFIX_) or any }
)IPFW";
	EXPECT_TRUE(parse_rules(rules, true));
}

TEST(Parser, 058_Gapped)
{
	const auto rules = R"IPFW(
:BEGIN
add allow ip from any to { 642@7777:ddd:c00::/40 }
add allow ip from any to { 102a12f@7777:ddd:c00::/40 }
add allow ip from any to { f800/21@7777:ddd:c00::/40 }
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 059_GappedBadSyntax)
{
	const auto rules = R"IPFW(
:BEGIN
add allow ip from any to { 100500640@7777:ddd:c00::/40 }
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 060_GappedBadSyntax)
{
	const auto rules = R"IPFW(
:BEGIN
add allow ip from any to { f800/0@7777:ddd:c00::/40 }
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 061_GappedBadSyntax)
{
	const auto rules = R"IPFW(
:BEGIN
add allow ip from any to { f800/128@7777:ddd:c00::/40 }
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 062_BadInclude)
{
	const auto rules = R"IPFW(
:BEGIN
add allow ip from any to { 10.16.1.1 or 10.16.2.1 }
add allow ip from { 10.16.1.1 or 10.16.2.1 } to any
add skipto :ENDOFME ip from any to any

# exception if we can not open specified file
include "firewall.next.conf"
)IPFW";
	EXPECT_ANY_THROW(parse_rules(rules));
}

TEST(Parser, 063_BadInclude)
{
	const auto rules = R"IPFW(
:BEGIN
add allow ip from any to { 10.16.1.1 or 10.16.2.1 }
add allow ip from { 10.16.1.1 or 10.16.2.1 } to any
add skipto :ENDOFME ip from any to any

# bad syntax
include "firewall.next.con
)IPFW";
	EXPECT_FALSE(parse_rules(rules));
}

TEST(Parser, 064_ViaOptionsIn)
{
	const auto rules = R"IPFW(
add skipto :WIN ip from any to any { via o19 or via o20 } in
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

TEST(Parser, 065_SkiptoDotDash)
{
	const auto rules = R"IPFW(
add skipto :BEGIN-section.service ip from any to any
:BEGIN-section.service
)IPFW";
	EXPECT_TRUE(parse_rules(rules));
}

} // namespace
