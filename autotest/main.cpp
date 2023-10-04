#include <signal.h>

#include <iostream>

#include "common/result.h"

#include "autotest.h"
#include "common.h"

common::log::LogPriority common::log::logPriority = common::log::TLOG_DEBUG;

nAutotest::tAutotest autotest;

void handleSignal(int signalType)
{
	if (signalType == SIGINT)
	{
		YANET_LOG_DEBUG("signal: SIGINT\n");
		/// @todo: stop
	}
	else if (signalType == SIGPIPE)
	{
		YANET_LOG_DEBUG("signal: SIGPIPE\n");
	}
}

int main(int argc,
         char** argv)
{
	eResult result = eResult::success;

	size_t pathsIndex = 1;
	bool dumpPackets = true;
	if (argc > 1 && std::string(argv[1]) == "-n")
	{
		dumpPackets = false;
		pathsIndex = 2;
	}
	std::vector<std::string> args(argv + pathsIndex, argv + argc);
	result = autotest.init(argv[0], dumpPackets, args);
	if (result != eResult::success)
	{
		return 2;
	}

	/** @todo
	if (signal(SIGINT, handleSignal) == SIG_ERR)
	{
		return 3;
	}
	*/

	if (signal(SIGPIPE, handleSignal) == SIG_ERR)
	{
		return 3;
	}

	autotest.start();
	autotest.join();

	return 0;
}
