#include <gtest/gtest.h>

#include "controlplane/configparser.h"
#include "controlplane/errors.h"

namespace
{

TEST(IsolationConfig, ParsesUniqueIPv4AndIPv6Prefixes)
{
	config_parser_t parser({});
	const auto config = parser.loadConfig(".", {{"prefixesIsolatedCP", {"192.0.2.0/24", "2001:db8::/32", "192.0.2.0/24"}}});
	const std::set<common::ip_prefix_t> expected = {
	        common::ip_prefix_t(std::string("192.0.2.0/24")),
	        common::ip_prefix_t(std::string("2001:db8::/32"))};
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
	EXPECT_THROW(parser.loadConfig(".", {{"prefixesIsolatedCP", {"invalid-prefix"}}}), error_result_t);
}

}
