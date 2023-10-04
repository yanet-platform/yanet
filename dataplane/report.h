#pragma once

#include <thread>

#include <nlohmann/json.hpp>

#include "common/result.h"
#include "common/type.h"

#include "hashtable.h"
#include "type.h"

class cReport
{
public:
	cReport(cDataPlane* dataPlane);

	eResult init();
	void run();
	void stop();
	void join();

	nlohmann::json getReport();

protected:
	void mainLoop();

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

	std::thread thread;
	int serverSocket;
};
