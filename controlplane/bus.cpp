#include <fcntl.h>
#include <memory.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <vector>

#include <nlohmann/json.hpp>

#include "common/icp.h"
#include "common/stream.h"

#include "bus.h"
#include "controlplane.h"

using controlplane::module::bus;

bus::bus() :
        serverSocket(-1)
{
}

bus::~bus()
{
	if (serverSocket != -1)
	{
		shutdown(serverSocket, SHUT_RDWR);
		close(serverSocket);
	}
}

eResult bus::init()
{
	serverSocket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (serverSocket < 0)
	{
		serverSocket = -1;
		return eResult::errorSocket;
	}

	funcThreads.emplace_back([this]() { serverThread(); });

	return eResult::success;
}

void bus::stop()
{
	if (serverSocket != -1)
	{
		shutdown(serverSocket, SHUT_RDWR);
		close(serverSocket);
		unlink(common::icp::socketPath);
	}
}

void bus::serverThread()
{
	sockaddr_un address;
	memset((char*)&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, common::icp::socketPath, sizeof(address.sun_path) - 1);
	address.sun_path[sizeof(address.sun_path) - 1] = 0;

	unlink(common::icp::socketPath);

	if (bind(serverSocket, (struct sockaddr*)&address, sizeof(address)) < 0)
	{
		YANET_LOG_ERROR("bind()\n");
		return;
	}

	chmod(common::icp::socketPath, 0770);

	if (listen(serverSocket, 64) < 0)
	{
		YANET_LOG_ERROR("listen()\n");
		return;
	}

	for (;;)
	{
		struct sockaddr_in6 address;
		socklen_t addressLength = sizeof(address);
		int clientSocket = accept(serverSocket, (struct sockaddr*)&address, &addressLength);
		if (clientSocket < 0)
		{
			continue;
		}

		std::thread([this, clientSocket] { clientThread(clientSocket); }).detach();
	}

	serverSocket = -1;
}

void bus::clientThread(int clientSocket)
{
	std::vector<uint8_t> buffer;

	for (;;)
	{
		uint64_t messageSize;
		if (auto err = common::recvAll(clientSocket, (char*)&messageSize, sizeof(messageSize)); err != 0)
		{
			/// @todo: log
			close(clientSocket);
			return;
		}

		buffer.resize(messageSize);
		if (auto err = common::recvAll(clientSocket, (char*)buffer.data(), buffer.size()); err != 0)
		{
			/// @todo: log
			close(clientSocket);
			return;
		}

		common::icp::request request;
		common::icp::response response = std::tuple<>{};

		{
			common::stream_in_t stream(buffer);
			stream.pop(request);
			if (stream.isFailed())
			{
				/// @todo: stats
				close(clientSocket);
				return;
			}
		}

		const common::icp::requestType& type = std::get<0>(request);
		if (exist(controlPlane->commands, type))
		{
			const auto start = std::chrono::steady_clock::now();

			response = controlPlane->commands[type](request);

			controlPlane->durations.add(std::string("command.") + common::icp::requestType_toString(type), start);
		}
		else
		{
			YANET_LOG_ERROR("unknown command: '%u'\n", (uint32_t)type);
			/// @todo: stats
			close(clientSocket);
			return;
		}

		if (auto err = common::send(clientSocket, response); err != 0)
		{
			/// @todo: stats
			close(clientSocket);
			return;
		}
	}

	close(clientSocket);
}
