#pragma once

#include <string>

#include <google/protobuf/message.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "stream.h"

namespace common
{

static inline int recvAll(int clientSocket,
                          char* buffer,
                          uint64_t size)
{
	uint64_t totalRecv = 0;

	while (totalRecv < size)
	{
		ssize_t ret = recv(clientSocket, buffer + totalRecv, size - totalRecv, MSG_NOSIGNAL);
		if (ret < 0)
		{
			return errno;
		}
		else if (ret == 0)
		{
			return -1; // EOF
		}

		totalRecv += ret;
	}
	return 0;
}

static inline int sendAll(int clientSocket,
                          const char* buffer,
                          uint64_t bufferSize)
{
	uint64_t totalSend = 0;

	while (totalSend < bufferSize)
	{
		ssize_t ret = send(clientSocket, buffer + totalSend, bufferSize - totalSend, MSG_NOSIGNAL);
		if (ret <= 0)
		{
			return errno;
		}

		totalSend += ret;
	}
	return 0;
}

template<class Req>
static int send(int clientSocket, const Req& request)
{
	if constexpr (std::is_convertible_v<Req&, ::google::protobuf::Message&>)
	{
#if GOOGLE_PROTOBUF_VERSION < 3001000
		uint64_t size = request.ByteSize();
#else
		uint64_t size = request.ByteSizeLong();
#endif
		std::vector<char> buf(size);

		if (!request.SerializeToArray(buf.data(), size))
		{
			return EBADMSG;
		}

		return (sendAll(clientSocket, (const char*)&size, sizeof(size)) ||
		        sendAll(clientSocket, buf.data(), size));
	}
	else
	{
		common::stream_out_t stream;
		stream.push(request);

		uint64_t messageSize = stream.getBuffer().size();
		return (sendAll(clientSocket, (const char*)&messageSize, sizeof(messageSize)) ||
		        sendAll(clientSocket, (const char*)stream.getBuffer().data(), messageSize));
	}
}

template<class Req>
static int send(int clientSocket, Req&& request)
{
	if constexpr (std::is_convertible_v<Req&, ::google::protobuf::Message&>)
	{
#if GOOGLE_PROTOBUF_VERSION < 3001000
		uint64_t size = request.ByteSize();
#else
		uint64_t size = request.ByteSizeLong();
#endif
		std::vector<char> buf(size);

		if (!request.SerializeToArray(buf.data(), size))
		{
			return EBADMSG;
		}

		return (sendAll(clientSocket, (const char*)&size, sizeof(size)) ||
		        sendAll(clientSocket, buf.data(), size));
	}
	else
	{
		common::stream_out_t stream;
		stream.push(request);

		uint64_t messageSize = stream.getBuffer().size();
		return (sendAll(clientSocket, (const char*)&messageSize, sizeof(messageSize)) ||
		        sendAll(clientSocket, (const char*)stream.getBuffer().data(), messageSize));
	}
}

template<class Resp>
static inline Resp recv(int clientSocket) // unsafe
{
	std::vector<uint8_t> buffer;

	uint64_t messageSize;
	if (auto err = recvAll(clientSocket, (char*)&messageSize, sizeof(messageSize)); err != 0)
	{
		throw std::string("recv(): ") + strerror(err);
	}
	buffer.resize(messageSize);

	recvAll(clientSocket, (char*)buffer.data(), buffer.size());

	Resp response;
	if constexpr (std::is_convertible_v<Resp&, ::google::protobuf::Message&>)
	{
		if (!response.ParseFromArray((char*)buffer.data(), buffer.size()))
		{
			throw std::string("proto.parse.isFailed()");
		}
	}
	else
	{
		common::stream_in_t stream(buffer);

		stream.pop(response);
		if (stream.isFailed())
		{
			throw std::string("stream.isFailed()");
		}
	}
	return response;
}

template<class Resp, class Req>
static inline Resp sendAndRecv(int clientSocket, const Req& request)
{
	if (auto err = send(clientSocket, request); err != 0)
	{
		throw std::string("send(): ") + strerror(err);
	}
	return recv<Resp>(clientSocket);
}

template<class Resp, class Req>
static inline Resp sendAndRecv(int clientSocket, Req&& request)
{
	if (auto err = send(clientSocket, std::move(request)); err != 0)
	{
		throw std::string("send(): ") + strerror(err);
	}
	return recv<Resp>(clientSocket);
}

}
