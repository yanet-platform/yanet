#include <gtest/gtest.h>

#include <array>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

#include <sys/socket.h>
#include <unistd.h>

#include "common/sendrecv.h"
#include "controlplane/controlplane.h"
#include "controlplane/protobus.h"
#include "libprotobuf/controlplane.pb.h"
#include "libprotobuf/meta.pb.h"

namespace
{

class throwing_service_t : public common::icp_proto::BalancerService
{
public:
	void Real(google::protobuf::RpcController*, const common::icp_proto::BalancerRealRequest*, common::icp_proto::Empty*, google::protobuf::Closure*) override
	{
		throw std::invalid_argument("address type is not set");
	}
};

class services_t : public cControlPlane
{
public:
	using cControlPlane::services;
};

class bus_t : public controlplane::module::protoBus
{
public:
	explicit bus_t(cControlPlane* owner) { controlPlane = owner; }
	using protoBus::clientThread;
};

class ProtoBus : public ::testing::Test
{
protected:
	void SetUp() override
	{
		ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()), 0);
		owner->services["BalancerService"] = &service;
		common::proto::RpcMeta meta;
		meta.set_service_name("BalancerService");
		meta.set_method_name("Real");
		ASSERT_EQ(common::send(sockets[0], meta), 0);
	}

	void TearDown() override { close(sockets[0]); }

	// The bus closes its socket when it stops serving the client.
	bool served_and_closed()
	{
		bus.clientThread(sockets[1]);
		char byte;
		return recv(sockets[0], &byte, 1, 0) == 0;
	}

	std::array<int, 2> sockets{-1, -1};
	throwing_service_t service;
	std::unique_ptr<services_t> owner = std::make_unique<services_t>();
	bus_t bus{owner.get()};
};

TEST_F(ProtoBus, InvalidRequestClosesConnection)
{
	ASSERT_EQ(common::send(sockets[0], common::icp_proto::BalancerRealRequest()), 0);
	EXPECT_TRUE(served_and_closed());
}

TEST_F(ProtoBus, OversizedRequestClosesConnection)
{
	const uint64_t size = std::numeric_limits<uint64_t>::max();
	ASSERT_EQ(common::sendAll(sockets[0], reinterpret_cast<const char*>(&size), sizeof(size)), 0);
	EXPECT_TRUE(served_and_closed());
}

}
