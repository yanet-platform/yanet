#pragma once

#include <json.hpp>

#include "type.h"

/// Provides various reports about the current state of the dataplane in JSON format.
class cReport
{
public:
	explicit cReport(cDataPlane* dataPlane);

	/// Returns the current state of the dataplane.
	///
	/// This function is not marked as const, because eventually it calls DPDK
	/// functions, which in its turn call driver's functions, which can
	/// modify its own state.
	///
	/// As a result, this method itself is not thread-safe. Be careful calling
	/// DPDK functions in multiple threads parallel with this method.
	nlohmann::json getReport();

protected:
	nlohmann::json convertWorker(const cWorker* worker);
	nlohmann::json convertWorkerGC(const worker_gc_t* worker);
	nlohmann::json convertMempool(const rte_mempool* mempool);
	nlohmann::json convertPort(const tPortId& portId);
	nlohmann::json convertControlPlane(const cControlPlane* controlPlane);
	nlohmann::json convertBus(const cBus* bus);
	nlohmann::json convertGlobalBaseAtomic(const dataplane::globalBase::atomic* globalBaseAtomic);
	nlohmann::json convertGlobalBase(const dataplane::globalBase::generation* globalBase);

protected:
	cDataPlane* dataPlane;
};
