#pragma once

#include <string>

#include <google/protobuf/message.h>
#include <google/protobuf/service.h>
#include <sys/un.h>

#include "libprotobuf/meta.pb.h"

#include "sendrecv.h"

namespace common::proto
{

class UnixProtobufRpcChannel : public google::protobuf::RpcChannel
{
public:
	UnixProtobufRpcChannel(const std::string& socketPath)
	{
		connectChannel(socketPath);
	}

	~UnixProtobufRpcChannel()
	{
		if (clientSocket != -1)
		{
			close(clientSocket);
		}
	}

	void connectChannel(const std::string& socketPath) const
	{
		if (clientSocket != -1)
		{
			/// already connected
			return;
		}

		clientSocket = socket(AF_UNIX, SOCK_STREAM, 0);
		if (clientSocket == -1)
		{
			//			YANET_LOG_ERROR("socket()\n");
			throw std::string("socket(): ") + strerror(errno);
		}

		sockaddr_un address;
		memset((char*)&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		strncpy(address.sun_path, socketPath.data(), sizeof(address.sun_path) - 1);
		address.sun_path[sizeof(address.sun_path) - 1] = 0;

		int ret = connect(clientSocket, (struct sockaddr*)&address, sizeof(address));
		if (ret == -1)
		{
			//			YANET_LOG_ERROR("connect()\n");
			throw std::string("connect(): ") + strerror(errno);
		}
	}

	virtual void CallMethod(const ::google::protobuf::MethodDescriptor* method,
	                        ::google::protobuf::RpcController* controller,
	                        const ::google::protobuf::Message* request,
	                        ::google::protobuf::Message* response,
	                        ::google::protobuf::Closure*)
	{
		std::lock_guard<std::mutex> guard(mutex);
		// Get the service name method name and fill it into rpc_meta
		common::proto::RpcMeta rpc_meta;
		rpc_meta.set_service_name(method->service()->name());
		rpc_meta.set_method_name(method->name());

		if (auto err = common::send(clientSocket, rpc_meta); err != 0)
		{
			controller->SetFailed(std::string("send meta: ") + strerror(err));
			return;
		}
		// single request
		if (auto err = common::send(clientSocket, *request); err != 0)
		{
			controller->SetFailed(std::string("send request: ") + strerror(err));
			return;
		}

		// single response

		uint64_t messageSize = 0;
		if (auto err = common::recvAll(clientSocket, (char*)&messageSize, sizeof(messageSize)); err != 0)
		{
			controller->SetFailed(std::string("recv response: ") + strerror(err));
			return;
		}
		buffer.resize(messageSize);

		common::recvAll(clientSocket, (char*)buffer.data(), buffer.size());

		if (!response->ParseFromArray((char*)buffer.data(), buffer.size()))
		{
			controller->SetFailed(std::string("response parse failed"));
		}
	}

private:
	mutable int clientSocket{-1};
	mutable std::mutex mutex{};
	std::vector<uint8_t> buffer;
};
}
