#include <gtest/gtest.h>

#include "controlplane/telegraf.h"

namespace
{

class telegraf_test_t : public telegraf_t
{
public:
	using telegraf_t::dregress_traffic;
};

route::tunnel_counter_key_t tunnel(uint32_t peer)
{
	return {true, peer, common::ip_address_t("192.0.2." + std::to_string(peer)), 64512};
}

TEST(TelegrafRetention, PeerWithoutCountersIsPruned)
{
	telegraf_test_t telegraf;
	telegraf.dregress_traffic({{tunnel(1), {1, 10}}, {tunnel(2), {1, 10}}});
	telegraf.dregress_traffic({{tunnel(1), {2, 20}}, {tunnel(2), {2, 20}}});

	const auto response = telegraf.dregress_traffic({{tunnel(1), {3, 30}}});

	EXPECT_EQ(std::get<0>(response).size(), 1u);
}

}
