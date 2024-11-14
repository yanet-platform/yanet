#pragma once

#include "libprotobuf/controlplane.pb.h"

#include "icp_proto.h"
#include "rpc_channel.h"
#include "rpc_controller.h"

namespace interface
{
class protoControlPlane
{
public:
	protoControlPlane(common::proto::UnixProtobufRpcChannel* channel = new common::proto::UnixProtobufRpcChannel(common::icp_proto::socketPath)) :
	        stub(channel)
	{
	}

	auto balancer_inspect_lookup(const common::icp_proto::BalancerInspectLookupRequest& request)
	{
		common::proto::RpcController ctl;
		common::icp_proto::BalancerInspectLookupResponse response;
		stub.InspectLookup(&ctl, &request, &response, nullptr);
		return response;
	}

	auto balancer_real_flush()
	{
		common::icp_proto::Empty request;
		common::proto::RpcController ctl;
		common::icp_proto::Empty response;
		stub.RealFlush(&ctl, &request, &response, nullptr);
		if (ctl.Failed())
		{
			throw std::string("rpc error: " + ctl.ErrorText());
		}
	}

	auto balancer_real_find(const common::icp_proto::BalancerRealFindRequest& request)
	{
		common::proto::RpcController ctl;
		common::icp_proto::BalancerRealFindResponse response;
		stub.RealFind(&ctl, &request, &response, nullptr);
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
		stub.Real(&ctl, &request, &response, nullptr);
		if (ctl.Failed())
		{
			throw std::string("rpc error: " + ctl.ErrorText());
		}
	}

protected:
	common::icp_proto::BalancerService::Stub stub;
};
}
