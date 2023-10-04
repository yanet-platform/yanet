#include <signal.h>
#include <systemd/sd-daemon.h>

#include <iostream>

#include "controlplane.h"

cControlPlane application;

void handleSignal(int signalType)
{
	if (signalType == SIGINT)
	{
		YANET_LOG_INFO("signal: SIGINT\n");
	}
	else if (signalType == SIGPIPE)
	{
		YANET_LOG_INFO("signal: SIGPIPE\n");
	}
}

int main(int argc,
         char** argv)
{
	int config = argc;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-d") == 0)
		{
			common::log::logPriority = common::log::TLOG_DEBUG;
		}
		else if (strcmp(argv[i], "-c") == 0)
		{
			config = i + 1;
		}
	}

	std::string jsonFilePath = "";
	if (config < argc)
	{
		jsonFilePath = argv[config];
	}

	if (application.init(jsonFilePath) != eResult::success)
	{
		return 1;
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

	sd_notify(0, "READY=1");

	application.start();
	application.join();
	return 0;
}
