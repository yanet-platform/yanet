#pragma once

#include <inttypes.h>

namespace common
{

enum class result_e : uint32_t
{
	success,
	errorAllocatingMemory,
	errorAllocatingKernelInterface,
	errorInitEal,
	errorInitBarrier,
	errorInitMempool,
	errorInitEthernetDevice,
	errorInitQueue,
	errorInitRing,
	errorCreateThread,
	errorOpenFile,
	errorSocket,
	errorBind,
	errorListen,
	errorConnect,
	invalidId,
	invalidCoreId,
	invalidSocketId,
	invalidConfigurationFile,
	invalidPrefix,
	invalidValueId,
	invalidPortId,
	invalidPortsCount,
	invalidInterfaceName,
	invalidCoresCount,
	invalidCount,
	invalidCounterId,
	invalidWorkerPortId,
	invalidNeighbor,
	invalidNexthop,
	invalidLogicalPortId,
	invalidVlanId,
	invalidVrfId,
	invalidFlow,
	invalidDecapId,
	invalidInterfaceId,
	invalidNat64statefulId,
	invalidNat64statelessId,
	invalidNat64statelessTranslationId,
	invalidAclId,
	invalidType,
	invalidArguments,
	invalidPhysicalPortName,
	invalidRing,
	isFull,
	isEmpty,
	unsupported,
	unsupportedDevice,
	alreadyExist,
	invalidMulticastIPv6Address,
	dataplaneIsBroken,
	invalidJson,
	missingRequiredOption,
	invalidTun64Id,
	errorInitSharedMemory,
};

static constexpr const char* result_to_c_str(common::result_e e)
{
	using common::result_e;

	switch (e)
	{
		case result_e::success:
			return "success";
		case result_e::errorAllocatingMemory:
			return "errorAllocatingMemory";
		case result_e::errorAllocatingKernelInterface:
			return "errorAllocatingKernelInterface";
		case result_e::errorInitEal:
			return "errorInitEal";
		case result_e::errorInitBarrier:
			return "errorInitBarrier";
		case result_e::errorInitMempool:
			return "errorInitMempool";
		case result_e::errorInitEthernetDevice:
			return "errorInitEthernetDevice";
		case result_e::errorInitQueue:
			return "errorInitQueue";
		case result_e::errorInitRing:
			return "errorInitRing";
		case result_e::errorCreateThread:
			return "errorCreateThread";
		case result_e::errorOpenFile:
			return "errorOpenFile";
		case result_e::errorSocket:
			return "errorSocket";
		case result_e::errorBind:
			return "errorBind";
		case result_e::errorListen:
			return "errorListen";
		case result_e::errorConnect:
			return "errorConnect";
		case result_e::invalidId:
			return "invalidId";
		case result_e::invalidCoreId:
			return "invalidCoreId";
		case result_e::invalidSocketId:
			return "invalidSocketId";
		case result_e::invalidConfigurationFile:
			return "invalidConfigurationFile";
		case result_e::invalidPrefix:
			return "invalidPrefix";
		case result_e::invalidValueId:
			return "invalidValueId";
		case result_e::invalidPortId:
			return "invalidPortId";
		case result_e::invalidPortsCount:
			return "invalidPortsCount";
		case result_e::invalidInterfaceName:
			return "invalidInterfaceName";
		case result_e::invalidCoresCount:
			return "invalidCoresCount";
		case result_e::invalidCount:
			return "invalidCount";
		case result_e::invalidCounterId:
			return "invalidCounterId";
		case result_e::invalidWorkerPortId:
			return "invalidWorkerPortId";
		case result_e::invalidNeighbor:
			return "invalidNeighbor";
		case result_e::invalidNexthop:
			return "invalidNexthop";
		case result_e::invalidLogicalPortId:
			return "invalidLogicalPortId";
		case result_e::invalidVlanId:
			return "invalidVlanId";
		case result_e::invalidVrfId:
			return "invalidVrfId";
		case result_e::invalidFlow:
			return "invalidFlow";
		case result_e::invalidDecapId:
			return "invalidDecapId";
		case result_e::invalidInterfaceId:
			return "invalidInterfaceId";
		case result_e::invalidNat64statefulId:
			return "invalidNat64statefulId";
		case result_e::invalidNat64statelessId:
			return "invalidNat64statelessId";
		case result_e::invalidNat64statelessTranslationId:
			return "invalidNat64statelessTranslationId";
		case result_e::invalidAclId:
			return "invalidAclId";
		case result_e::invalidType:
			return "invalidType";
		case result_e::invalidArguments:
			return "invalidArguments";
		case result_e::invalidPhysicalPortName:
			return "invalidPhysicalPortName";
		case result_e::invalidRing:
			return "invalidRing";
		case result_e::isFull:
			return "isFull";
		case result_e::isEmpty:
			return "isEmpty";
		case result_e::unsupported:
			return "unsupported";
		case result_e::unsupportedDevice:
			return "unsupportedDevice";
		case result_e::alreadyExist:
			return "alreadyExist";
		case result_e::invalidMulticastIPv6Address:
			return "invalidMulticastIPv6Address";
		case result_e::dataplaneIsBroken:
			return "dataplaneIsBroken";
		case result_e::invalidJson:
			return "invalidJson";
		case result_e::missingRequiredOption:
			return "missingRequiredOption";
		case result_e::invalidTun64Id:
			return "invalidTun64Id";
		case result_e::errorInitSharedMemory:
			return "errorInitSharedMemory";
	}

	return "?";
}

}

using eResult = common::result_e;
