#pragma once

#include "helper.h"
#include "influxdb_format.h"
#include "table_printer.h"

namespace bus
{

using bus_request_info = std::tuple<std::string, uint64_t, uint64_t>;

inline std::vector<bus_request_info> get_bus_requests(common::sdp::DataPlaneInSharedMemory& sdp_data)
{
	auto [requests, errors, durations] = sdp_data.BuffersBus();
	GCC_BUG_UNUSED(errors);

	std::map<common::idp::requestType, std::string> names = {
	        {common::idp::requestType::updateGlobalBase, "updateGlobalBase"},
	        {common::idp::requestType::updateGlobalBaseBalancer, "updateGlobalBaseBalancer"},
	        {common::idp::requestType::getGlobalBase, "getGlobalBase"},
	        {common::idp::requestType::getWorkerStats, "getWorkerStats"},
	        {common::idp::requestType::getSlowWorkerStats, "getSlowWorkerStats"},
	        {common::idp::requestType::clearWorkerDumpRings, "clearWorkerDumpRings"},
	        {common::idp::requestType::get_worker_gc_stats, "get_worker_gc_stats"},
	        {common::idp::requestType::get_dregress_counters, "get_dregress_counters"},
	        {common::idp::requestType::get_ports_stats, "get_ports_stats"},
	        {common::idp::requestType::get_ports_stats_extended, "get_ports_stats_extended"},
	        {common::idp::requestType::getControlPlanePortStats, "getControlPlanePortStats"},
	        {common::idp::requestType::getPortStatsEx, "getPortStatsEx"},
	        {common::idp::requestType::getFragmentationStats, "getFragmentationStats"},
	        {common::idp::requestType::getFWState, "getFWState"},
	        {common::idp::requestType::getFWStateStats, "getFWStateStats"},
	        {common::idp::requestType::clearFWState, "clearFWState"},
	        {common::idp::requestType::getConfig, "getConfig"},
	        {common::idp::requestType::getErrors, "getErrors"},
	        {common::idp::requestType::getReport, "getReport"},
	        {common::idp::requestType::lpm4LookupAddress, "lpm4LookupAddress"},
	        {common::idp::requestType::lpm6LookupAddress, "lpm6LookupAddress"},
	        {common::idp::requestType::nat64stateful_state, "nat64stateful_state"},
	        {common::idp::requestType::balancer_connection, "balancer_connection"},
	        {common::idp::requestType::balancer_service_connections, "balancer_service_connections"},
	        {common::idp::requestType::balancer_real_connections, "balancer_real_connections"},
	        {common::idp::requestType::limits, "limits"},
	        {common::idp::requestType::samples, "samples"},
	        {common::idp::requestType::hitcount_dump, "hitcount_dump"},
	        {common::idp::requestType::debug_latch_update, "debug_latch_update"},
	        {common::idp::requestType::unrdup_vip_to_balancers, "unrdup_vip_to_balancers"},
	        {common::idp::requestType::update_vip_vport_proto, "update_vip_vport_proto"},
	        {common::idp::requestType::version, "version"},
	        {common::idp::requestType::get_shm_info, "get_shm_info"},
	        {common::idp::requestType::get_shm_tsc_info, "get_shm_tsc_info"},
	        {common::idp::requestType::set_shm_tsc_state, "set_shm_tsc_state"},
	        {common::idp::requestType::dump_physical_port, "dump_physical_port"},
	        {common::idp::requestType::balancer_state_clear, "balancer_state_clear"},
	        {common::idp::requestType::neighbor_show, "neighbor_show"},
	        {common::idp::requestType::neighbor_insert, "neighbor_insert"},
	        {common::idp::requestType::neighbor_remove, "neighbor_remove"},
	        {common::idp::requestType::neighbor_clear, "neighbor_clear"},
	        {common::idp::requestType::neighbor_flush, "neighbor_flush"},
	        {common::idp::requestType::neighbor_update_interfaces, "neighbor_update_interfaces"},
	        {common::idp::requestType::neighbor_stats, "neighbor_stats"},
	        {common::idp::requestType::memory_manager_update, "memory_manager_update"},
	        {common::idp::requestType::memory_manager_stats, "memory_manager_stats"}};

	std::vector<bus_request_info> result;
	for (uint32_t index = 0; index < (uint32_t)common::idp::requestType::size; ++index)
	{
		if ((requests[index] != 0) || (durations[index] != 0))
		{
			const auto& iter = names.find(static_cast<common::idp::requestType>(index));
			result.emplace_back((iter != names.end() ? iter->second : "unknown"), requests[index], durations[index]);
		}
	}

	return result;
}

inline void bus_requests()
{
	common::sdp::DataPlaneInSharedMemory sdp_data;
	OpenSharedMemoryDataplaneBuffers(sdp_data, false);
	auto requests = get_bus_requests(sdp_data);

	TablePrinter table;
	table.insert_row("request", "count", "duration_ms");
	for (const auto& [request, count, duration] : requests)
	{
		if ((count != 0) || (duration != 0))
		{
			table.insert_row(request, count, duration);
		}
	}

	table.Print();
}

inline std::vector<std::pair<std::string, uint64_t>> get_bus_errors(const common::sdp::DataPlaneInSharedMemory& sdp_data)
{
	auto [requests, errors, durations] = sdp_data.BuffersBus();
	GCC_BUG_UNUSED(requests);
	GCC_BUG_UNUSED(durations);

	std::map<common::idp::errorType, std::string> names = {
	        {common::idp::errorType::busRead, "busRead"},
	        {common::idp::errorType::busWrite, "busWrite"},
	        {common::idp::errorType::busParse, "busParse"},
	};

	std::vector<std::pair<std::string, uint64_t>> result;
	for (uint32_t index = 0; index < (uint32_t)common::idp::errorType::size; ++index)
	{
		const auto& iter = names.find(static_cast<common::idp::errorType>(index));
		result.emplace_back((iter != names.end() ? iter->second : "unknown"), errors[index]);
	}

	return result;
}

inline void bus_errors()
{
	common::sdp::DataPlaneInSharedMemory sdp_data;
	OpenSharedMemoryDataplaneBuffers(sdp_data, false);
	auto errors = get_bus_errors(sdp_data);

	FillAndPrintTable({"error", "count"}, errors);
}

inline void bus_telegraf()
{
	common::sdp::DataPlaneInSharedMemory sdp_data;
	OpenSharedMemoryDataplaneBuffers(sdp_data, false);

	auto errors = get_bus_errors(sdp_data);
	std::vector<influxdb_format::value_t> infl_errors;
	for (const auto& [error, count] : errors)
	{
		infl_errors.emplace_back(error.data(), count);
	}
	influxdb_format::print("bus_errors", {}, infl_errors);

	auto requests = get_bus_requests(sdp_data);
	if (!requests.empty())
	{
		std::vector<influxdb_format::value_t> infl_counts;
		std::vector<influxdb_format::value_t> infl_durations;
		for (const auto& [request, count, duration] : requests)
		{
			infl_counts.emplace_back(request.data(), count);
			infl_durations.emplace_back(request.data(), duration);
		}
		influxdb_format::print("bus_counts", {}, infl_counts);
		influxdb_format::print("bus_durations", {}, infl_durations);
	}
}

} // namespace bus
