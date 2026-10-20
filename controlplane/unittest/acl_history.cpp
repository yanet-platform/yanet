#include <gtest/gtest.h>

#include <limits>
#include <memory>

#include "controlplane/controlplane.h"

namespace
{

class history_t : public cControlPlane
{
public:
	using cControlPlane::addConfig;
	using cControlPlane::command_getAclConfig;

	auto configCount() const
	{
		return configs.size();
	}
};

TEST(AclHistory, DropsParsedFirewall)
{
	auto history = std::make_unique<history_t>();
	controlplane::base_t config;
	config.acls["acl0"].firewall = std::make_shared<ipfw::fw_config_t>(2);
	const std::weak_ptr<ipfw::fw_config_t> firewall = config.acls["acl0"].firewall;

	history->addConfig(1, config);
	config = controlplane::base_t();

	EXPECT_TRUE(firewall.expired());
}

TEST(AclHistory, ReturnsStoredMetadata)
{
	auto history = std::make_unique<history_t>();
	controlplane::base_t config;
	config.ids_map = {{}, {7, 8}};

	history->addConfig(3, config);

	EXPECT_EQ(history->command_getAclConfig(3), (common::icp::getAclConfig::response{3, config.result_iface_map, config.ids_map}));
}

TEST(AclHistory, RetainsOnlyFiveRecentConfigs)
{
	auto history = std::make_unique<history_t>();
	controlplane::base_t config;
	for (uint32_t serial = 1; serial <= 7; ++serial)
	{
		history->addConfig(serial, config);
	}

	EXPECT_EQ(history->configCount(), 5u);
	for (uint32_t serial = 1; serial <= 2; ++serial)
	{
		EXPECT_EQ(history->command_getAclConfig(serial), common::icp::getAclConfig::response{});
	}
	for (uint32_t serial = 3; serial <= 7; ++serial)
	{
		EXPECT_EQ(history->command_getAclConfig(serial), (common::icp::getAclConfig::response{serial, config.result_iface_map, config.ids_map}));
	}
}

TEST(AclHistory, UpdatesMetadataAtCapacityWithoutEviction)
{
	auto history = std::make_unique<history_t>();
	controlplane::base_t config;
	config.ids_map = {{}, {7, 8}};
	for (uint32_t serial = 1; serial <= 5; ++serial)
	{
		history->addConfig(serial, config);
	}

	config.ids_map = {{}, {9, 10}};
	history->addConfig(3, config);

	EXPECT_EQ(history->configCount(), 5u);
	EXPECT_EQ(history->command_getAclConfig(3), (common::icp::getAclConfig::response{3, config.result_iface_map, config.ids_map}));
	for (uint32_t serial = 1; serial <= 5; ++serial)
	{
		EXPECT_EQ(std::get<0>(history->command_getAclConfig(serial)), serial);
	}
}

TEST(AclHistory, EvictsOldSuccessorAfterSerialWrap)
{
	auto history = std::make_unique<history_t>();
	controlplane::base_t config;
	config.ids_map = {{}, {7, 8}};
	const auto lastSerial = std::numeric_limits<uint32_t>::max();
	for (uint32_t offset = 0; offset < 5; ++offset)
	{
		history->addConfig(lastSerial - offset, config);
	}
	history->addConfig(0, config);

	EXPECT_EQ(history->configCount(), 5u);
	EXPECT_EQ(history->command_getAclConfig(lastSerial - 4), common::icp::getAclConfig::response{});
	EXPECT_EQ(history->command_getAclConfig(0), (common::icp::getAclConfig::response{0, config.result_iface_map, config.ids_map}));
	for (uint32_t offset = 0; offset < 4; ++offset)
	{
		EXPECT_EQ(std::get<0>(history->command_getAclConfig(lastSerial - offset)), lastSerial - offset);
	}
}

}
