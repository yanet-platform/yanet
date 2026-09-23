#include <gtest/gtest.h>

#include <limits>
#include <vector>

#include "controlplane/configparser.h"
#include "controlplane/errors.h"

TEST(IsolationConfig, ParsesDestinationPrefixesFromRules)
{
	config_parser_t parser({});
	const nlohmann::json rules = {
	        {"dscp", {48}},
	        {"dstPrefixes", {"192.0.2.252/32", "2001:db8::1/128"}},
	};
	const auto config = parser.loadConfig(".", {{"rulesIsolatedCP", rules}});
	const std::set<common::ip_prefix_t> expected = {
	        common::ip_prefix_t("192.0.2.252/32"),
	        common::ip_prefix_t("2001:db8::1/128")};
	EXPECT_EQ(config.prefixes_isolated_cp, expected);
	EXPECT_EQ(config.dscp_isolated_cp, (std::set<uint8_t>{48}));
}

TEST(IsolationConfig, ParsesUniqueDscpValuesWithoutPrefixes)
{
	config_parser_t parser({});
	const auto config = parser.loadConfig(".", {{"rulesIsolatedCP", {{"dscp", {0, 48, 63, 48}}}}});
	EXPECT_EQ(config.dscp_isolated_cp, (std::set<uint8_t>{0, 48, 63}));
	EXPECT_TRUE(config.prefixes_isolated_cp.empty());
}

TEST(IsolationConfig, RejectsLegacyPrefixesSyntax)
{
	config_parser_t parser({});
	EXPECT_THROW(parser.loadConfig(".", {{"prefixesIsolatedCP", {"192.0.2.0/24"}}}), error_result_t);
}

TEST(IsolationConfig, RejectsMalformedRules)
{
	config_parser_t parser({});
	const std::vector<nlohmann::json> invalid_rules = {
	        nullptr,
	        48,
	        "48",
	        nlohmann::json::array(),
	        {{"dscp", 48}},
	        {{"dscp", {64}}},
	        {{"dscp", {-1}}},
	        {{"dscp", {256}}},
	        {{"dscp", {48.5}}},
	        {{"dscp", {"48"}}},
	        {{"dscp", {true}}},
	        {{"dscp", {nullptr}}},
	        {{"dscp", {std::numeric_limits<uint64_t>::max()}}},
	        {{"dscp", nullptr}},
	        {{"dscp", nlohmann::json::object()}},
	        {{"dstPrefixes", nullptr}},
	        {{"dstPrefixes", "192.0.2.0/24"}},
	        {{"dstPrefixes", {"192.0.2.0/33"}}},
	        {{"bufferId", 1}},
	};
	for (const auto& rules : invalid_rules)
	{
		SCOPED_TRACE(rules.dump());
		EXPECT_THROW(parser.loadConfig(".", {{"rulesIsolatedCP", rules}}), error_result_t);
	}
}

TEST(IsolationConfig, ParsesUniqueIPv4AndIPv6Prefixes)
{
	config_parser_t parser({});
	const nlohmann::json prefixes = {
	        "192.0.2.0/24", "2001:db8::/32", "192.0.2.0/24", "0.0.0.0/0", "::/0", "192.0.2.1", "192.0.2.1/32", "192.0.2.1/032", "2001:db8::1", "2001:db8::1/128", "2001:db8::1/0128", "::ffff:192.0.2.1", "::ffff:192.0.2.1/128", "::ffff:c000:201/128"};
	const auto config = parser.loadConfig(".", {{"rulesIsolatedCP", {{"dstPrefixes", prefixes}}}});
	const std::set<common::ip_prefix_t> expected = {
	        common::ip_prefix_t("192.0.2.0/24"), common::ip_prefix_t("2001:db8::/32"), common::ip_prefix_t("0.0.0.0/0"), common::ip_prefix_t("::/0"), common::ip_prefix_t("192.0.2.1/32"), common::ip_prefix_t("2001:db8::1/128"), common::ip_prefix_t("::ffff:c000:201/128")};
	EXPECT_EQ(config.prefixes_isolated_cp, expected);
	EXPECT_TRUE(config.dscp_isolated_cp.empty());
}

TEST(IsolationConfig, MissingOrEmptyRulesClearConfiguration)
{
	config_parser_t parser({});
	for (const auto& json : std::vector<nlohmann::json>{
	             nlohmann::json::object(),
	             {{"rulesIsolatedCP", nlohmann::json::object()}},
	             {{"rulesIsolatedCP", {{"dscp", nlohmann::json::array()}, {"dstPrefixes", nlohmann::json::array()}}}}})
	{
		const auto config = parser.loadConfig(".", json);
		EXPECT_TRUE(config.prefixes_isolated_cp.empty());
		EXPECT_TRUE(config.dscp_isolated_cp.empty());
	}
}

TEST(IsolationConfig, RejectsMalformedPrefixes)
{
	config_parser_t parser({});
	for (const auto* prefix : {"invalid-prefix", "192.0.2.0/33", "2001:db8::/129", "192.0.2.0/256", "2001:db8::/384", "192.0.2.0/-1", "2001:db8::/-256", "192.0.2.0/99999999999999999999", "192.0.2.0/32junk", "2001:db8::/128/0", "192.0.2.0/", "192.0.2.0/+24", "2001:db8::/-0", "192.0.2.0/ 24", "2001:db8::/128 ", "192.0.2.0/0x20"})
	{
		SCOPED_TRACE(prefix);
		EXPECT_THROW(parser.loadConfig(".", {{"rulesIsolatedCP", {{"dstPrefixes", {prefix}}}}}), error_result_t);
	}
}
