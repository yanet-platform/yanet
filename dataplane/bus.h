#pragma once

#include <arpa/inet.h>

#include <thread>
#include <variant>
#include <array>
#include <vector>

#include <rte_ether.h>

#include "common/result.h"
#include "common/idp.h"
#include "common/type.h"

#include "type.h"

class cBus
{
public:
	cBus(cDataPlane* dataPlane);

	eResult init();
	void run();
	void stop();
	void join();

protected:
	void mainLoop();
	void clientThread(int clientSocket);

protected:
	void call(void (cControlPlane::*function)(), const common::idp::request& request)
	{
		(void)request; ///< @todo: [[maybe_unused]]
		(controlPlane->*function)();
	}

	template<typename TArg>
	void call(void (cControlPlane::*function)(const TArg&), const common::idp::request& request)
	{
		(controlPlane->*function)(std::get<TArg>(std::get<1>(request)));
	}

	template<typename TResult>
	TResult callWithResponse(TResult (cControlPlane::*function)(), const common::idp::request& request)
	{
		(void)request; ///< @todo: [[maybe_unused]]
		return (controlPlane->*function)();
	}

	template<typename TResult>
	TResult callWithResponse(TResult (cControlPlane::*function)() const, const common::idp::request& request) const
	{
		(void)request; ///< @todo: [[maybe_unused]]
		return (controlPlane->*function)();
	}

	template<typename TResult,
	         typename TArg>
	TResult callWithResponse(TResult (cControlPlane::*function)(const TArg&), const common::idp::request& request)
	{
		return (controlPlane->*function)(std::get<TArg>(std::get<1>(request)));
	}

protected:
	friend class cReport;

	struct sStats
	{
		sStats()
		{
			memset(this, 0, sizeof(*this));
		}

		uint64_t requests[(uint32_t)common::idp::requestType::size];
		uint64_t errors[(uint32_t)common::idp::errorType::size];
	} stats;

	cDataPlane* dataPlane;
	cControlPlane* controlPlane;

	std::thread thread;
	int serverSocket;
};
