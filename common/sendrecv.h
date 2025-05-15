#pragma once

#include <string>

#include <cstring>
#include <google/protobuf/message.h>
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
static int send(int clientSocket, Req&& request)
{
	if constexpr (std::is_base_of_v<::google::protobuf::Message, std::decay_t<Req>>)
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
		stream.push(std::forward<Req>(request));

		uint64_t messageSize = stream.getBuffer().size();
		return (sendAll(clientSocket, (const char*)&messageSize, sizeof(messageSize)) ||
		        sendAll(clientSocket, (const char*)stream.getBuffer().data(), messageSize));
	}
}

template<class Req>
int send_with_fd(int clientSocket, Req&& request, int fd_to_send)
{
	uint64_t messageSize = 0;
	std::vector<char> buf;

	if constexpr (std::is_base_of_v<::google::protobuf::Message, std::decay_t<Req>>)
	{
#if GOOGLE_PROTOBUF_VERSION < 3001000
		messageSize = request.ByteSize();
#else
		messageSize = request.ByteSizeLong();
#endif
		buf.resize(messageSize);
		if (!request.SerializeToArray(buf.data(), messageSize))
		{
			return EBADMSG;
		}
	}
	else
	{
		common::stream_out_t stream;
		stream.push(std::forward<Req>(request));
		const auto& tmp = stream.getBuffer();
		messageSize = tmp.size();
		buf.assign(tmp.begin(), tmp.end());
	}

	// Send messageSize as with regular `send<>`
	if (int err = sendAll(clientSocket, (const char*)&messageSize, sizeof(messageSize)))
		return err;

	// iovec describes an array of buffers to be sent; here, a single message.
	struct iovec iov;
	iov.iov_base = buf.data();
	iov.iov_len = buf.size();

	// msghdr describes the full message including iovec and control data.
	char cmsg_buf[CMSG_SPACE(sizeof(int))] = {};
	struct msghdr msg = {};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (fd_to_send >= 0)
	{
		msg.msg_control = cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);

		struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS; // Indicates passing of file descriptors.
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
	}

	// Send message buffer with fd attached
	ssize_t ret = sendmsg(clientSocket, &msg, MSG_NOSIGNAL);
	if (ret < 0)
		return errno;

	return 0;
}

template<class Resp>
static inline Resp recv(int clientSocket) // unsafe
{
	std::vector<uint8_t> buffer;

	uint64_t messageSize = 0;
	if (auto err = recvAll(clientSocket, (char*)&messageSize, sizeof(messageSize)); err != 0)
	{
		throw std::string("recv(): ") + strerror(err);
	}
	buffer.resize(messageSize);

	recvAll(clientSocket, (char*)buffer.data(), buffer.size());

	Resp response;
	if constexpr (std::is_base_of_v<::google::protobuf::Message, std::decay_t<Resp>>)
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
static inline Resp sendAndRecv(int clientSocket, Req&& request)
{
	if (auto err = send(clientSocket, std::forward<Req>(request)); err != 0)
	{
		throw std::string("send(): ") + strerror(err);
	}
	return recv<Resp>(clientSocket);
}

template<class Resp, class Req>
inline Resp send_and_recv_with_fd(int clientSocket, Req&& request, int fd_to_send)
{
	if (auto err = send_with_fd(clientSocket, std::forward<Req>(request), fd_to_send); err != 0)
	{
		throw std::string("send_with_fd(): ") + strerror(err);
	}
	return recv<Resp>(clientSocket);
}

}
