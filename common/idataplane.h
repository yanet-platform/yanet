#pragma once

#include <mutex>

#include <sys/un.h>

#include "idp.h"
#include "result.h"
#include "sendrecv.h"

namespace interface
{

class dataPlane
{
public:
	dataPlane() = default;

	~dataPlane()
	{
		if (clientSocket != -1)
		{
			close(clientSocket);
		}
	}

public:
	auto updateGlobalBase(const common::idp::updateGlobalBase::request& request) const
	{
		return get<common::idp::requestType::updateGlobalBase, common::idp::updateGlobalBase::response>(request);
	}

	eResult updateGlobalBaseBalancer(const common::idp::updateGlobalBaseBalancer::request& request) const
	{
		return get<common::idp::requestType::updateGlobalBaseBalancer, common::idp::updateGlobalBaseBalancer::response>(request);
	}

	common::idp::lpm4LookupAddress::response lpm4LookupAddress(const common::idp::lpm4LookupAddress::request& request) const
	{
		return get<common::idp::requestType::lpm4LookupAddress, common::idp::lpm4LookupAddress::response>(request);
	}

	common::idp::lpm6LookupAddress::response lpm6LookupAddress(const common::idp::lpm6LookupAddress::request& request) const
	{
		return get<common::idp::requestType::lpm6LookupAddress, common::idp::lpm6LookupAddress::response>(request);
	}

	common::idp::getWorkerStats::response getWorkerStats(const common::idp::getWorkerStats::request& request) const
	{
		return get<common::idp::requestType::getWorkerStats, common::idp::getWorkerStats::response>(request);
	}

	auto getSlowWorkerStats() const
	{
		return get<common::idp::requestType::getSlowWorkerStats, common::idp::getSlowWorkerStats::response>();
	}

	auto clearWorkerDumpRings() const
	{
		return get<common::idp::requestType::clearWorkerDumpRings, eResult>();
	}

	auto flushDumpRing(const common::idp::flushDumpRing::request& request) const
	{
		return get<common::idp::requestType::flushDumpRing, eResult>(request);
	}

	auto get_worker_gc_stats() const
	{
		return get<common::idp::requestType::get_worker_gc_stats, common::idp::get_worker_gc_stats::response>();
	}

	auto get_dregress_counters() const
	{
		return get<common::idp::requestType::get_dregress_counters, common::idp::get_dregress_counters::response>();
	}

	auto get_ports_stats() const
	{
		return get<common::idp::requestType::get_ports_stats, common::idp::get_ports_stats::response>();
	}

	auto get_ports_stats_extended() const
	{
		return get<common::idp::requestType::get_ports_stats_extended, common::idp::get_ports_stats_extended::response>();
	}

	common::idp::getControlPlanePortStats::response getControlPlanePortStats(const common::idp::getControlPlanePortStats::request& request) const
	{
		return get<common::idp::requestType::getControlPlanePortStats, common::idp::getControlPlanePortStats::response>(request);
	}

	common::idp::getFragmentationStats::response getFragmentationStats() const
	{
		return get<common::idp::requestType::getFragmentationStats, common::idp::getFragmentationStats::response>();
	}

	common::idp::getFWState::response getFWState() const
	{
		return get<common::idp::requestType::getFWState, common::idp::getFWState::response>();
	}

	common::idp::getFWStateStats::response getFWStateStats() const
	{
		return get<common::idp::requestType::getFWStateStats, common::idp::getFWStateStats::response>();
	}

	eResult clearFWState() const
	{
		return get<common::idp::requestType::clearFWState, eResult>();
	}

	common::idp::getPortStatsEx::response getPortStatsEx() const
	{
		return get<common::idp::requestType::getPortStatsEx, common::idp::getPortStatsEx::response>();
	}

	common::idp::getConfig::response getConfig() const
	{
		return get<common::idp::requestType::getConfig, common::idp::getConfig::response>();
	}

	common::idp::getErrors::response getErrors() const
	{
		return get<common::idp::requestType::getErrors, common::idp::getErrors::response>();
	}

	common::idp::getReport::response getReport() const
	{
		return get<common::idp::requestType::getReport, common::idp::getReport::response>();
	}

	common::idp::getGlobalBase::response getGlobalBase(const common::idp::getGlobalBase::request& request) const
	{
		return get<common::idp::requestType::getGlobalBase, common::idp::getGlobalBase::response>(request);
	}

	auto nat64stateful_state(const common::idp::nat64stateful_state::request& request) const
	{
		return get<common::idp::requestType::nat64stateful_state, common::idp::nat64stateful_state::response>(request);
	}

	auto balancer_connection(const common::idp::balancer_connection::request& request) const
	{
		return get<common::idp::requestType::balancer_connection, common::idp::balancer_connection::response>(request);
	}

	auto balancer_service_connections() const
	{
		return get<common::idp::requestType::balancer_service_connections, common::idp::balancer_service_connections::response>();
	}

	auto balancer_real_connections() const
	{
		return get<common::idp::requestType::balancer_real_connections, common::idp::balancer_real_connections::response>();
	}

	auto limits() const
	{
		return get<common::idp::requestType::limits, common::idp::limits::response>();
	}

	auto samples() const
	{
		return get<common::idp::requestType::samples, common::idp::samples::response>();
	}

	auto hitcount_dump() const
	{
		return get<common::idp::requestType::hitcount_dump, common::idp::hitcount_dump::response>();
	}

	eResult debug_latch_update(const common::idp::debug_latch_update::request& request) const
	{
		return get<common::idp::requestType::debug_latch_update, common::idp::debug_latch_update::response>(request);
	}

	eResult unrdup_vip_to_balancers(const common::idp::unrdup_vip_to_balancers::request& request) const
	{
		return get<common::idp::requestType::unrdup_vip_to_balancers, common::idp::unrdup_vip_to_balancers::response>(request);
	}

	eResult update_vip_vport_proto(const common::idp::update_vip_vport_proto::request& request) const
	{
		return get<common::idp::requestType::update_vip_vport_proto, common::idp::update_vip_vport_proto::response>(request);
	}

	auto version() const
	{
		return get<common::idp::requestType::version, common::idp::version::response>();
	}

	auto get_shm_info() const
	{
		return get<common::idp::requestType::get_shm_info, common::idp::get_shm_info::response>();
	}

	auto get_shm_tsc_info() const
	{
		return get<common::idp::requestType::get_shm_tsc_info, common::idp::get_shm_tsc_info::response>();
	}

	auto dump_physical_port(const common::idp::dump_physical_port::request& request) const
	{
		return get<common::idp::requestType::dump_physical_port, eResult>(request);
	}

	auto balancer_state_clear() const
	{
		return get<common::idp::requestType::balancer_state_clear, eResult>();
	}

	auto neighbor_show() const
	{
		return get<common::idp::requestType::neighbor_show, common::idp::neighbor_show::response>();
	}

	auto neighbor_insert(const common::idp::neighbor_insert::request& request) const
	{
		return get<common::idp::requestType::neighbor_insert, eResult>(request);
	}

	auto neighbor_remove(const common::idp::neighbor_remove::request& request) const
	{
		return get<common::idp::requestType::neighbor_remove, eResult>(request);
	}

	auto neighbor_clear() const
	{
		return get<common::idp::requestType::neighbor_clear, eResult>();
	}

	auto neighbor_flush() const
	{
		return get<common::idp::requestType::neighbor_flush, eResult>();
	}

	auto neighbor_update_interfaces(const common::idp::neighbor_update_interfaces::request& request) const
	{
		return get<common::idp::requestType::neighbor_update_interfaces, eResult>(request);
	}

	auto neighbor_stats() const
	{
		return get<common::idp::requestType::neighbor_stats, common::idp::neighbor_stats::response>();
	}

	auto memory_manager_update(const common::idp::memory_manager_update::request& request) const
	{
		return get<common::idp::requestType::memory_manager_update, eResult>(request);
	}

	auto memory_manager_stats() const
	{
		return get<common::idp::requestType::memory_manager_stats, common::idp::memory_manager_stats::response>();
	}

protected:
	void connectToDataPlane() const
	{
		if (clientSocket != -1)
		{
			/// already connected
			return;
		}

		clientSocket = socket(AF_UNIX, SOCK_STREAM, 0);
		if (clientSocket == -1)
		{
			throw std::string("socket(): ") + strerror(errno);
		}

		sockaddr_un address;
		memset((char*)&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		strncpy(address.sun_path, common::idp::socketPath, sizeof(address.sun_path) - 1);
		address.sun_path[sizeof(address.sun_path) - 1] = 0;

		int ret = connect(clientSocket, (struct sockaddr*)&address, sizeof(address));
		if (ret == -1)
		{
			int error = errno;
			YANET_LOG_ERROR("Error connect to socket %s, error: %d - %s\n",
			                common::idp::socketPath,
			                error,
			                strerror(error));
			throw std::string("connect(): ") + strerror(error);
		}
	}

	template<common::idp::requestType T, class Resp, class Req = std::tuple<>>
	Resp get(const Req& request = Req()) const
	{
		return std::get<Resp>(call<T>(request));
	}

	template<common::idp::requestType T, class Req>
	common::idp::response call(const Req& request) const
	{
		std::lock_guard<std::mutex> guard(mutex);
		connectToDataPlane();
		return common::sendAndRecv<common::idp::response>(clientSocket, common::idp::request(T, request));
	}

	template<common::idp::requestType T, class Resp, class Req>
	Resp get(Req&& request) const
	{
		return std::get<Resp>(call<T>(std::move(request)));
	}

	template<common::idp::requestType T, class Req>
	common::idp::response call(Req&& request) const
	{
		std::lock_guard<std::mutex> guard(mutex);
		connectToDataPlane();
		return common::sendAndRecv<common::idp::response>(clientSocket, common::idp::request(T, std::move(request)));
	}

protected:
	mutable int clientSocket{-1};
	mutable std::mutex mutex;
};

}
