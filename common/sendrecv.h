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

/**
 * @brief Send an entire buffer (and optional FD) via sendmsg()
 *
 * @param client     Socket the socket to send on
 * @param data       Pointer to the buffer to send
 * @param dataLen    Number of bytes in data
 * @param fd_to_send File descriptor to SCM_RIGHTS-attach.
 *                   If < 0, no FD is attached.
 *
 * @return 0 on success, or an errno on failure
 */
static inline int sendMsgAll(int clientSocket,
                             const char* data,
                             size_t dataLen,
                             int fd_to_send = -1)
{
	size_t totalSent = 0;
	bool fdPassed = false;

	while (totalSent < dataLen)
	{
		size_t remain = dataLen - totalSent;

		// prepare msghdr
		struct msghdr msg;
		memset(&msg, 0, sizeof(msg));

		struct iovec iov;
		iov.iov_base = (void*)(data + totalSent);
		iov.iov_len = remain;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		// attach the FD only the first time
		char cmsg_buf[CMSG_SPACE(sizeof(int))];
		memset(cmsg_buf, 0, sizeof(cmsg_buf));

		if (!fdPassed && fd_to_send >= 0)
		{
			msg.msg_control = cmsg_buf;
			msg.msg_controllen = sizeof(cmsg_buf);

			struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN(sizeof(int));
			memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
		}

		// attempt to send
		ssize_t sent = sendmsg(clientSocket, &msg, MSG_NOSIGNAL);

		if (sent < 0)
		{
			// if EAGAIN/EINTR, you can decide whether to retry
			return errno;
		}
		if (sent == 0)
		{
			// peer closed?
			return -1;
		}

		// mark FD passed so we don't pass it again
		if (!fdPassed && fd_to_send >= 0)
			fdPassed = true;

		totalSent += size_t(sent);
	} // end while

	return 0;
}

/**
 *@brief Receive an exact number of bytes (messageSize) with recvmsg(),
 *       collecting a single FD if passed.
 *
 * If you expect multiple calls (or large messages) be aware that a single FD,
 * if attached, might arrive in any “chunk.”
 *
 *@param client  Socket the socket to receive from
 *@param buffer  Storage for the incoming data; must be already resized to messageSize
 *@param message Size how many bytes we expect to read into buffer
 *@param outFd   Optional output parameter for single received FD.
 *
 *@return 0 on success, or an errno / negative if error
 */
static inline int recvMsgAll(int clientSocket,
                             unsigned char* buffer,
                             size_t messageSize,
                             int& outFd)
{
	outFd = -1; // default to no FD
	size_t totalRecv = 0;

	while (totalRecv < messageSize)
	{
		size_t remain = messageSize - totalRecv;

		// set up msghdr
		struct msghdr msg;
		memset(&msg, 0, sizeof(msg));

		struct iovec iov;
		iov.iov_base = (void*)(buffer + totalRecv);
		iov.iov_len = remain;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		char cmsg_buf[CMSG_SPACE(sizeof(int))];
		memset(cmsg_buf, 0, sizeof(cmsg_buf));
		msg.msg_control = cmsg_buf;
		msg.msg_controllen = sizeof(cmsg_buf);

		ssize_t n = recvmsg(clientSocket, &msg, MSG_NOSIGNAL);
		if (n < 0)
		{
			return errno;
		}
		if (n == 0)
		{
			// peer closed
			return -1;
		}

		totalRecv += size_t(n);

		// parse control message only once if we haven't found an FD
		// if an FD is attached multiple times, we only grab the first
		if (outFd < 0)
		{
			for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
			     cmsg != nullptr;
			     cmsg = CMSG_NXTHDR(&msg, cmsg))
			{
				if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
				{
					memcpy(&outFd, CMSG_DATA(cmsg), sizeof(int));
					break;
				}
			}
		}
	}

	// have read messageSize bytes exactly
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

	return sendMsgAll(clientSocket, buf.data(), buf.size(), fd_to_send);
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
