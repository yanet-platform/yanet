#pragma once

#include "libprotobuf/controlplane.pb.h"

#include "icp.h"
#include "sendrecv.h"

namespace common::icp_proto
{
	constexpr inline char socketPath[] = "/run/yanet/protocontrolplane.sock";
}
