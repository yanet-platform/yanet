#include <vector>

#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/icp.h"
#include "common/icp_proto.h"
#include "libprotobuf/meta.pb.h"

#include "controlplane.h"
#include "protobus.h"

using controlplane::module::protoBus;

protoBus::protoBus() :
        serverSocket(-1)
{
}

protoBus::~protoBus()
{
	if (serverSocket != -1)
	{
		shutdown(serverSocket, SHUT_RDWR);
		close(serverSocket);
	}
}

eResult protoBus::init()
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

void protoBus::stop()
{
	if (serverSocket != -1)
	{
		shutdown(serverSocket, SHUT_RDWR);
		close(serverSocket);
		unlink(common::icp::socketPath);
	}
}

void protoBus::serverThread()
{
	sockaddr_un address;
	memset((char*)&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, common::icp_proto::socketPath, sizeof(address.sun_path) - 1);
	address.sun_path[sizeof(address.sun_path) - 1] = 0;

	unlink(common::icp_proto::socketPath);

	if (bind(serverSocket, (struct sockaddr*)&address, sizeof(address)) < 0)
	{
		YANET_LOG_ERROR("bind()\n");
		return;
	}

	chmod(common::icp_proto::socketPath, 0770);

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

void protoBus::clientThread(int clientSocket)
{
	std::vector<uint8_t> buffer;

	for (;;)
	{
		uint64_t messageSize;
		if (auto err = common::recvAll(clientSocket, (char*)&messageSize, sizeof(messageSize)); err != 0)
		{
			if (err > 0)
			{
				YANET_LOG_WARNING("recv error: %s", strerror(err));
			} // -1 is regular close
			close(clientSocket);
			return;
		}

		if (messageSize > 1 << 20)
		{
			// meta > 1MB is shit
			YANET_LOG_WARNING("too big meta size: %lu", messageSize);
			close(clientSocket);
			return;
		}

		buffer.resize(messageSize);
		if (auto err = common::recvAll(clientSocket, (char*)buffer.data(), buffer.size()); err != 0)
		{
			if (err > 0)
			{
				YANET_LOG_WARNING("recv error: %s", strerror(err));
			} // -1 is regular close
			close(clientSocket);
			return;
		}
		common::proto::RpcMeta rpc_meta;
		if (!rpc_meta.ParseFromArray(buffer.data(), buffer.size()))
		{
			YANET_LOG_WARNING("bad metadata");
			close(clientSocket);
			return;
		}

		auto* service = controlPlane->services[rpc_meta.service_name()];
		if (!service)
		{
			YANET_LOG_WARNING("service '%s' not found", rpc_meta.service_name().c_str());
			close(clientSocket);
			return;
		}

		auto* method = service->GetDescriptor()->FindMethodByName(rpc_meta.method_name());
		if (!method)
		{
			YANET_LOG_WARNING("method '%s' not found in service '%s'", rpc_meta.method_name().c_str(), rpc_meta.service_name().c_str());
			close(clientSocket);
			return;
		}
		auto* request = service->GetRequestPrototype(method).New();
		auto* response = service->GetResponsePrototype(method).New();

		if (auto err = common::recvAll(clientSocket, (char*)&messageSize, sizeof(messageSize)); err != 0)
		{
			if (err > 0)
			{
				YANET_LOG_WARNING("recv error: %s", strerror(err));
			} // -1 is regular close
			close(clientSocket);
			return;
		}
		buffer.resize(messageSize);
		if (auto err = common::recvAll(clientSocket, (char*)buffer.data(), buffer.size()); err != 0)
		{
			if (err > 0)
			{
				YANET_LOG_WARNING("recv error: %s", strerror(err));
			} // -1 is regular close
			close(clientSocket);
			return;
		}
		if (!request->ParseFromArray(buffer.data(), buffer.size()))
		{
			YANET_LOG_WARNING("bad request");
			close(clientSocket);
			return;
		}

		// todo process errors through controller
		service->CallMethod(method, nullptr, request, response, nullptr);

		if (auto err = common::send(clientSocket, *response); err != 0)
		{
			YANET_LOG_WARNING("send error: %s", strerror(err));
			close(clientSocket);
			return;
		}
		delete request;
		delete response;
	}

	close(clientSocket);
}
