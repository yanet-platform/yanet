#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/stream.h"

#include "bus.h"
#include "common.h"
#include "controlplane.h"
#include "dataplane.h"

cBus::cBus(cDataPlane* dataPlane) :
        dataPlane(dataPlane),
        serverSocket(-1)
{
}

eResult cBus::init()
{
	controlPlane = dataPlane->controlPlane.get();
	serverSocket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (serverSocket < 0)
	{
		serverSocket = -1;
		return eResult::errorSocket;
	}

	return eResult::success;
}

void cBus::run()
{
	thread = std::thread([this] { mainLoop(); });
}

void cBus::stop()
{
	if (serverSocket != -1)
	{
		shutdown(serverSocket, SHUT_RDWR);
		close(serverSocket);
		unlink(common::idp::socketPath);
	}
}

void cBus::join()
{
	if (thread.joinable())
	{
		thread.join();
	}
}

uint64_t cBus::GetSizeForCounters()
{
	auto count_errors = static_cast<uint32_t>(common::idp::errorType::size);
	auto count_requests = static_cast<uint32_t>(common::idp::requestType::size);
	return (count_errors + 2 * count_requests) * sizeof(uint64_t);
}

void cBus::SetBufferForCounters(const common::sdp::DataPlaneInSharedMemory& sdp_data)
{
	auto [requests, errors, durations] = sdp_data.BuffersBus();
	stats.requests = requests;
	stats.errors = errors;
	stats.durations = durations;
}

static bool recvAll(int clientSocket,
                    char* buffer,
                    uint64_t size)
{
	uint64_t totalRecv = 0;

	while (totalRecv < size)
	{
		int ret = recv(clientSocket, buffer + totalRecv, size - totalRecv, MSG_NOSIGNAL);
		if (ret <= 0)
		{
			return false;
		}

		totalRecv += ret;
	}

	return true;
}

static bool sendAll(int clientSocket,
                    const char* buffer,
                    uint64_t bufferSize)
{
	uint64_t totalSend = 0;

	while (totalSend < bufferSize)
	{
		int ret = send(clientSocket, buffer + totalSend, bufferSize - totalSend, MSG_NOSIGNAL);
		if (ret <= 0)
		{
			return false;
		}

		totalSend += ret;
	}

	return true;
}

void cBus::mainLoop()
{
	sockaddr_un address;
	memset((char*)&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, common::idp::socketPath, sizeof(address.sun_path) - 1);
	address.sun_path[sizeof(address.sun_path) - 1] = 0;

	unlink(common::idp::socketPath);

	if (bind(serverSocket, (struct sockaddr*)&address, sizeof(address)) < 0)
	{
		auto ec = errno;
		YADECAP_LOG_ERROR("bind(): %d\n", ec);
		return;
	}

	chmod(common::idp::socketPath, 0770);

	if (listen(serverSocket, 64) < 0)
	{
		auto ec = errno;
		YADECAP_LOG_ERROR("listen(): %d\n", ec);
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

static const uint32_t BigMessage = 1024 * 1024 * 1024;

void cBus::clientThread(int clientSocket)
{
	std::vector<uint8_t> buffer;

	for (;;)
	{
		uint64_t messageSize = 0;
		if (!recvAll(clientSocket, (char*)&messageSize, sizeof(messageSize)))
		{
			stats.errors[(uint32_t)common::idp::errorType::busRead]++;
			break;
		}

		auto startTime = std::chrono::system_clock::now();

		if (messageSize > BigMessage)
		{
			YANET_LOG_DEBUG("reading %lu bytes message\n", messageSize);
		}
		buffer.resize(messageSize);
		if (!recvAll(clientSocket, (char*)buffer.data(), buffer.size()))
		{
			stats.errors[(uint32_t)common::idp::errorType::busRead]++;
			break;
		}

		common::idp::request request;
		common::idp::response response = std::tuple<>();

		if (messageSize > BigMessage)
		{
			YANET_LOG_DEBUG("parsing %lu bytes message\n", messageSize);
		}

		{
			common::stream_in_t stream(buffer);
			stream.pop(request);
			if (stream.isFailed())
			{
				stats.errors[(uint32_t)common::idp::errorType::busParse]++;
				break;
			}
		}

		if (messageSize > BigMessage)
		{
			YANET_LOG_DEBUG("free message buffer memory\n");

			// free memory from above 1Gb messages
			buffer.clear();
			buffer.shrink_to_fit();
		}

		const common::idp::requestType& type = std::get<0>(request);
		YANET_LOG_DEBUG("request type %d\n", (int)type);
		if (type == common::idp::requestType::updateGlobalBase)
		{
			response = callWithResponse(&cControlPlane::updateGlobalBase, request);
		}
		else if (type == common::idp::requestType::updateGlobalBaseBalancer)
		{
			response = callWithResponse(&cControlPlane::updateGlobalBaseBalancer, request);
		}
		else if (type == common::idp::requestType::getGlobalBase)
		{
			response = callWithResponse(&cControlPlane::getGlobalBase, request);
		}
		else if (type == common::idp::requestType::getWorkerStats)
		{
			response = callWithResponse(&cControlPlane::getWorkerStats, request);
		}
		else if (type == common::idp::requestType::getSlowWorkerStats)
		{
			response = callWithResponse(&cControlPlane::SlowWorkerStatsResponse, request);
		}
		else if (type == common::idp::requestType::clearWorkerDumpRings)
		{
			response = callWithResponse(&cControlPlane::clearWorkerDumpRings, request);
		}
		else if (type == common::idp::requestType::get_worker_gc_stats)
		{
			response = callWithResponse(&cControlPlane::get_worker_gc_stats, request);
		}
		else if (type == common::idp::requestType::get_dregress_counters)
		{
			response = callWithResponse(&cControlPlane::get_dregress_counters, request);
		}
		else if (type == common::idp::requestType::get_ports_stats)
		{
			response = callWithResponse(&cControlPlane::get_ports_stats, request);
		}
		else if (type == common::idp::requestType::get_ports_stats_extended)
		{
			response = callWithResponse(&cControlPlane::get_ports_stats_extended, request);
		}
		else if (type == common::idp::requestType::getControlPlanePortStats)
		{
			response = callWithResponse(&cControlPlane::getControlPlanePortStats, request);
		}
		else if (type == common::idp::requestType::getPortStatsEx)
		{
			response = callWithResponse(&cControlPlane::getPortStatsEx, request);
		}
		else if (type == common::idp::requestType::getFragmentationStats)
		{
			response = callWithResponse(&cControlPlane::getFragmentationStats, request);
		}
		else if (type == common::idp::requestType::getFWState)
		{
			response = callWithResponse(&cControlPlane::getFWState, request);
		}
		else if (type == common::idp::requestType::getFWStateStats)
		{
			response = callWithResponse(&cControlPlane::getFWStateStats, request);
		}
		else if (type == common::idp::requestType::clearFWState)
		{
			response = callWithResponse(&cControlPlane::clearFWState, request);
		}
		else if (type == common::idp::requestType::getConfig)
		{
			response = callWithResponse(&cControlPlane::getConfig, request);
		}
		else if (type == common::idp::requestType::getErrors)
		{
			response = callWithResponse(&cControlPlane::getErrors, request);
		}
		else if (type == common::idp::requestType::getReport)
		{
			response = callWithResponse(&cControlPlane::getReport, request);
		}
		else if (type == common::idp::requestType::lpm4LookupAddress)
		{
			response = callWithResponse(&cControlPlane::lpm4LookupAddress, request);
		}
		else if (type == common::idp::requestType::lpm6LookupAddress)
		{
			response = callWithResponse(&cControlPlane::lpm6LookupAddress, request);
		}
		else if (type == common::idp::requestType::limits)
		{
			response = callWithResponse(&cControlPlane::limits, request);
		}
		else if (type == common::idp::requestType::balancer_connection)
		{
			response = callWithResponse(&cControlPlane::balancer_connection, request);
		}
		else if (type == common::idp::requestType::balancer_service_connections)
		{
			response = callWithResponse(&cControlPlane::balancer_service_connections, request);
		}
		else if (type == common::idp::requestType::balancer_real_connections)
		{
			response = callWithResponse(&cControlPlane::balancer_real_connections, request);
		}
		else if (type == common::idp::requestType::samples)
		{
			response = callWithResponse(&cControlPlane::samples, request);
		}
		else if (type == common::idp::requestType::hitcount_dump)
		{
			response = callWithResponse(&cControlPlane::hitcount_dump, request);
		}
		else if (type == common::idp::requestType::debug_latch_update)
		{
			response = callWithResponse(&cControlPlane::debug_latch_update, request);
		}
		else if (type == common::idp::requestType::unrdup_vip_to_balancers)
		{
			response = callWithResponse(&cControlPlane::unrdup_vip_to_balancers, request);
		}
		else if (type == common::idp::requestType::update_vip_vport_proto)
		{
			response = callWithResponse(&cControlPlane::update_vip_vport_proto, request);
		}
		else if (type == common::idp::requestType::version)
		{
			response = callWithResponse(&cControlPlane::version, request);
		}
		else if (type == common::idp::requestType::nat64stateful_state)
		{
			response = callWithResponse(&cControlPlane::nat64stateful_state, request);
		}
		else if (type == common::idp::requestType::get_shm_info)
		{
			response = callWithResponse(&cControlPlane::get_shm_info, request);
		}
		else if (type == common::idp::requestType::get_shm_tsc_info)
		{
			response = callWithResponse(&cControlPlane::get_shm_tsc_info, request);
		}
		else if (type == common::idp::requestType::dump_physical_port)
		{
			response = callWithResponse(&cControlPlane::dump_physical_port, request);
		}
		else if (type == common::idp::requestType::balancer_state_clear)
		{
			response = callWithResponse(&cControlPlane::balancer_state_clear, request);
		}
		else if (type == common::idp::requestType::neighbor_show)
		{
			response = dataPlane->neighbor.neighbor_show();
		}
		else if (type == common::idp::requestType::neighbor_insert)
		{
			response = dataPlane->neighbor.neighbor_insert(std::get<common::idp::neighbor_insert::request>(std::get<1>(request)));
		}
		else if (type == common::idp::requestType::neighbor_remove)
		{
			response = dataPlane->neighbor.neighbor_remove(std::get<common::idp::neighbor_remove::request>(std::get<1>(request)));
		}
		else if (type == common::idp::requestType::neighbor_clear)
		{
			response = dataPlane->neighbor.neighbor_clear();
		}
		else if (type == common::idp::requestType::neighbor_flush)
		{
			response = dataPlane->neighbor.neighbor_flush();
		}
		else if (type == common::idp::requestType::neighbor_update_interfaces)
		{
			response = dataPlane->neighbor.neighbor_update_interfaces(std::get<common::idp::neighbor_update_interfaces::request>(std::get<1>(request)));
		}
		else if (type == common::idp::requestType::neighbor_stats)
		{
			response = dataPlane->neighbor.neighbor_stats();
		}
		else if (type == common::idp::requestType::memory_manager_update)
		{
			response = dataPlane->memory_manager.memory_manager_update(std::get<common::idp::memory_manager_update::request>(std::get<1>(request)));
		}
		else if (type == common::idp::requestType::memory_manager_stats)
		{
			response = dataPlane->memory_manager.memory_manager_stats();
		}
		else
		{
			stats.errors[(uint32_t)common::idp::errorType::busParse]++;
			break;
		}

		if ((uint32_t)type < (uint32_t)common::idp::requestType::size)
		{
			stats.requests[(uint32_t)type]++;
		}

		common::stream_out_t stream;
		stream.push(response);

		messageSize = stream.getBuffer().size();
		if ((!sendAll(clientSocket, (const char*)&messageSize, sizeof(messageSize))) ||
		    (!sendAll(clientSocket, (const char*)stream.getBuffer().data(), messageSize)))
		{
			stats.errors[(uint32_t)common::idp::errorType::busWrite]++;
			break;
		}

		std::chrono::duration<double> duration = std::chrono::system_clock::now() - startTime;

		// The duration time is measured in milliseconds
		stats.durations[(uint32_t)type] += static_cast<uint64_t>(1000 * duration.count());
		YANET_LOG_DEBUG("request type %d processed - %.3f sec\n",
		                (int)type,
		                duration.count());
	}

	close(clientSocket);
}
