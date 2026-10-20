#include <gtest/gtest.h>

#include "controlplane/balancer.h"

namespace
{

class reals_t : public balancer_t
{
public:
	using balancer_t::real_updates;
	using balancer_t::reals_enabled;
	using balancer_t::reals_unordered;
};

balancer::real_key_global_t real(int index)
{
	return {"balancer0", {common::ip_address_t("10.0.0.1"), IPPROTO_TCP, 80}, {common::ip_address_t("192.0.2." + std::to_string(index)), 8080}};
}

// Real 1 still owns a dataplane id (configured or awaiting counter GC), real 2 does not.
class BalancerPrune : public ::testing::Test
{
protected:
	void SetUp() override
	{
		reals.reals_unordered = {{real(1), 1}};
		reals.reals_enabled = {{real(1), 5}, {real(2), 7}};
		reals.real_updates = {real(1), real(2)};
		reals.prune_reals();
	}

	reals_t reals;
};

TEST_F(BalancerPrune, KeepsOnlyOverridesOfRealsWithIds)
{
	EXPECT_EQ(reals.reals_enabled, (decltype(reals.reals_enabled){{real(1), 5}}));
}

TEST_F(BalancerPrune, KeepsOnlyUpdatesOfRealsWithIds)
{
	EXPECT_EQ(reals.real_updates, (decltype(reals.real_updates){real(1)}));
}

}
