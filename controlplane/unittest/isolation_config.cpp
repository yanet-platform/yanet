#include <gtest/gtest.h>

#include "controlplane/configparser.h"
#include "controlplane/errors.h"

TEST(IsolationConfig, ParsesUniqueIPv4AndIPv6Prefixes)
{
	config_parser_t parser({});
	const nlohmann::json prefixes = {
	        "192.0.2.0/24", "2001:db8::/32", "192.0.2.0/24", "0.0.0.0/0", "::/0", "192.0.2.1", "192.0.2.1/32", "192.0.2.1/032", "2001:db8::1", "2001:db8::1/128", "2001:db8::1/0128", "::ffff:192.0.2.1", "::ffff:192.0.2.1/128", "::ffff:c000:201/128"};
	const auto config = parser.loadConfig(".", {{"prefixesIsolatedCP", prefixes}});
	const std::set<common::ip_prefix_t> expected = {
	        common::ip_prefix_t("192.0.2.0/24"), common::ip_prefix_t("2001:db8::/32"), common::ip_prefix_t("0.0.0.0/0"), common::ip_prefix_t("::/0"), common::ip_prefix_t("192.0.2.1/32"), common::ip_prefix_t("2001:db8::1/128"), common::ip_prefix_t("::ffff:c000:201/128")};
	EXPECT_EQ(config.prefixes_isolated_cp, expected);
}

TEST(IsolationConfig, MissingPrefixesClearConfiguration)
{
	config_parser_t parser({});
	EXPECT_TRUE(parser.loadConfig(".", nlohmann::json::object()).prefixes_isolated_cp.empty());
}

TEST(IsolationConfig, EmptyPrefixesClearConfiguration)
{
	config_parser_t parser({});
	EXPECT_TRUE(parser.loadConfig(".", {{"prefixesIsolatedCP", nlohmann::json::array()}}).prefixes_isolated_cp.empty());
}

TEST(IsolationConfig, RejectsMalformedPrefixes)
{
	config_parser_t parser({});
	for (const auto* prefix : {"invalid-prefix", "192.0.2.0/33", "2001:db8::/129", "192.0.2.0/256", "2001:db8::/384", "192.0.2.0/-1", "2001:db8::/-256", "192.0.2.0/99999999999999999999", "192.0.2.0/32junk", "2001:db8::/128/0", "192.0.2.0/", "192.0.2.0/+24", "2001:db8::/-0", "192.0.2.0/ 24", "2001:db8::/128 ", "192.0.2.0/0x20"})
	{
		SCOPED_TRACE(prefix);
		EXPECT_THROW(parser.loadConfig(".", {{"prefixesIsolatedCP", {prefix}}}), error_result_t);
	}
}
