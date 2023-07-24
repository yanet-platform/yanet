#pragma once

#include "libprotobuf/controlplane.pb.h"

#include "icp_proto.h"
#include "rpc_channel.h"
#include "rpc_controller.h"

namespace interface
{
class protoControlPlane : protected common::icp_proto::BalancerService::Stub
{
public:
	protoControlPlane(common::proto::UnixProtobufRpcChannel* channel = new common::proto::UnixProtobufRpcChannel(common::icp_proto::socketPath)) :
	        common::icp_proto::BalancerService::Stub(channel),
	        channel(channel)
	{
	}

	~protoControlPlane() override
	{
		delete channel;
	}

	auto balancer_real_flush()
	{
		common::icp_proto::Empty request;
		common::proto::RpcController ctl;
		common::icp_proto::Empty response;
		RealFlush(&ctl, &request, &response, nullptr);
		if (ctl.Failed())
		{
			throw std::string("rpc error: " + ctl.ErrorText());
		}
	}

	auto balancer_real_find(const common::icp_proto::BalancerRealFindRequest& request)
	{
		common::proto::RpcController ctl;
		common::icp_proto::BalancerRealFindResponse response;
		RealFind(&ctl, &request, &response, nullptr);
		if (ctl.Failed())
		{
			throw std::string("rpc error: " + ctl.ErrorText());
		}
		return response;
	}

	auto balancer_real(const common::icp_proto::BalancerRealRequest& request)
	{
		common::proto::RpcController ctl;
		common::icp_proto::Empty response;
		Real(&ctl, &request, &response, nullptr);
		if (ctl.Failed())
		{
			throw std::string("rpc error: " + ctl.ErrorText());
		}
	}

protected:
	common::proto::UnixProtobufRpcChannel* channel;
};
}
