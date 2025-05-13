#pragma once

#include "common/sdpcommon.h"
#include "controlplane.h"

class cBus
{
public:
	cBus(cDataPlane* dataPlane);

	eResult init();
	void run();
	void stop();
	void join();

	static uint64_t GetSizeForCounters();
	void SetBufferForCounters(const common::sdp::DataPlaneInSharedMemory& sdp_data);

protected:
	void mainLoop();
	void clientThread(int clientSocket);

protected:
	void call(void (cControlPlane::*function)(), [[maybe_unused]] const common::idp::request& request)
	{
		(controlPlane->*function)();
	}

	template<typename TArg>
	void call(void (cControlPlane::*function)(const TArg&), const common::idp::request& request)
	{
		(controlPlane->*function)(std::get<TArg>(std::get<1>(request)));
	}

	template<typename TResult>
	TResult callWithResponse(TResult (cControlPlane::*function)(), [[maybe_unused]] const common::idp::request& request)
	{
		return (controlPlane->*function)();
	}

	template<typename TResult>
	TResult callWithResponse(TResult (cControlPlane::*function)() const, [[maybe_unused]] const common::idp::request& request) const
	{
		return (controlPlane->*function)();
	}

	template<typename TResult,
	         typename TArg>
	TResult callWithResponse(TResult (cControlPlane::*function)(const TArg&), const common::idp::request& request)
	{
		return (controlPlane->*function)(std::get<TArg>(std::get<1>(request)));
	}

	template<typename TResult, typename TArg>
	TResult callWithResponse(TResult (cControlPlane::*function)(const TArg&, int), const common::idp::request& request, int fd)
	{
		return (controlPlane->*function)(std::get<TArg>(std::get<1>(request)), fd);
	}

protected:
	friend class cReport;

	struct sStats
	{
		uint64_t* requests; // common::idp::requestType::size
		uint64_t* errors; // common::idp::errorType::size
		uint64_t* durations; // common::idp::requestType::size
	} stats;

	cDataPlane* dataPlane;
	cControlPlane* controlPlane;

	std::thread thread;
	int serverSocket;
};
