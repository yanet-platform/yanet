#include <gtest/gtest.h>

#include "controlplane/rib.h"

namespace
{

class test_rib_t : public rib_t
{
public:
	using rib_t::nh_to_ref_count;
	using rib_t::summary;
};

const ip_address_t peer{"192.0.2.1"};
const ip_prefix_t prefix{"10.0.0.0/24"};

common::icp::rib_update::insert announce()
{
	common::icp::rib_update::insert request{"bgp", "default", 100, {}};
	auto& prefixes = std::get<3>(request)[{peer, "igp", 0, {64512}, {}, {}, 100}]["ipv4 unicast"][ip_address_t("192.0.2.2")];
	prefixes.emplace_back(prefix, "path", std::vector<uint32_t>{});
	return request;
}

common::icp::rib_update::remove withdraw(size_t copies = 1)
{
	common::icp::rib_update::remove request{"bgp", "default", 100, {}};
	auto& prefixes = std::get<3>(request)[peer]["ipv4 unicast"];
	prefixes.resize(copies, {prefix, "path", std::vector<uint32_t>{}});
	return request;
}

TEST(RIBMemory, DuplicateAnnouncementIsReleasedByOneWithdraw)
{
	test_rib_t rib;
	rib.rib_update({announce(), announce(), withdraw()});
	EXPECT_TRUE(rib.nh_to_ref_count.empty());
}

TEST(RIBMemory, WithdrawBatchStopsAfterSummaryIsErased)
{
	test_rib_t rib;
	rib.rib_update({announce(), withdraw(2)});
	EXPECT_TRUE(rib.summary.empty());
}

}
