#include <gtest/gtest.h>

#include "common/idp.h"
#include "common/stream.h"

namespace
{

TEST(IsolationRequest, PrefixesRoundTrip)
{
	const common::idp::updateGlobalBase::update_prefixes_isolated_cp::request prefixes = {
	        common::ip_prefix_t(std::string("192.0.2.0/24")),
	        common::ip_prefix_t(std::string("2001:db8::/32"))};
	const common::idp::updateGlobalBase::request request = {
	        {common::idp::updateGlobalBase::requestType::update_prefixes_isolated_cp, prefixes}};
	common::stream_out_t output;
	output.push(request);
	common::stream_in_t input(output.getBuffer());
	common::idp::updateGlobalBase::request decoded;
	input.pop(decoded);
	ASSERT_FALSE(input.isFailed());
	ASSERT_EQ(decoded.size(), 1u);
	EXPECT_EQ(std::get<0>(decoded.front()), std::get<0>(request.front()));
	EXPECT_EQ(std::get<common::idp::updateGlobalBase::update_prefixes_isolated_cp::request>(std::get<1>(decoded.front())), prefixes);
}

}
