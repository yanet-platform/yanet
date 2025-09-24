#pragma once

#include "type.h"

namespace balancer
{

enum class service_counter : tCounterId
{
	packets,
	bytes,
	real_disabled_packets,
	real_disabled_bytes,
	size
};

enum class real_counter : tCounterId
{
	packets,
	bytes,
	sessions_created,
	sessions_destroyed,
	size
};

using gc_real_counter = real_counter;

}

namespace nat64stateful
{

enum class module_counter : tCounterId
{
	lan_packets,
	lan_bytes,
	wan_packets,
	wan_bytes,
	pool_is_empty,
	tries_array_start,
	tries_array_end = tries_array_start + YANET_CONFIG_NAT64STATEFUL_INSERT_TRIES - 1,
	tries_failed,
	wan_state_not_found,
	wan_state_insert,
	wan_state_insert_failed = wan_state_insert,
	wan_state_insert_success,
	wan_state_cross_numa_insert,
	wan_state_cross_numa_insert_failed = wan_state_cross_numa_insert,
	wan_state_cross_numa_insert_success,
	lan_state_insert,
	lan_state_insert_failed = lan_state_insert,
	lan_state_insert_success,
	lan_state_cross_numa_insert,
	lan_state_cross_numa_insert_failed = lan_state_cross_numa_insert,
	lan_state_cross_numa_insert_success,
	size
};

}

namespace proxy
{

enum class service_counter : tCounterId
{
	forward_client_packets,
	forward_client_bytes,
	forward_service_packets,
	forward_service_bytes,
	syn_count,
	ping_count,
	syn_retransmits_count,
	syn_cookie_count,
	drop_client_packets,
	drop_client_bytes,
	drop_service_packets,
	drop_service_bytes,
	drop_blacklist,
	service_bucket_overflow,
	failed_local_pool_allocation,
	failed_local_pool_search_ack,
	failed_local_pool_search_syn_ack,
	failed_answer_service_syn_ack,
	ignored_size_update_detections,
	failed_check_syn_cookie,
	failed_search_client_service_ack,
	new_connections,
	new_syn_connections,
	success_check_syn_cookie,
	service_syn_ack_count,
	error_service_config_timestamps,
	error_service_config_sack,
	error_service_config_mss,
	ack_without_service_answer,
	ack_invalid_ack_number,
	pkts_with_corrupted_tcp_opts_client,
	pkts_with_corrupted_tcp_opts_service,
	rst_service,
	drop_connection_limit,
	drop_rate_limit,
	connection_limiter_new,
	connection_limiter_remove,
	connection_limiter_overflow,
	rate_limiter_overflow,
	size
};

inline const char* service_counter_toString(service_counter counter)
{
	switch (counter)
	{
		case service_counter::forward_client_packets:
			return "forward_client_packets";
		case service_counter::forward_client_bytes:
			return "forward_client_bytes";
		case service_counter::forward_service_packets:
			return "forward_service_packets";
		case service_counter::forward_service_bytes:
			return "forward_service_bytes";
		case service_counter::syn_count:
			return "syn_count";
		case service_counter::ping_count:
			return "ping_count";
		case service_counter::syn_retransmits_count:
			return "syn_retransmits_count";
		case service_counter::syn_cookie_count:
			return "syn_cookie_count";
		case service_counter::drop_client_packets:
			return "drop_client_packets";
		case service_counter::drop_client_bytes:
			return "drop_client_bytes";
		case service_counter::drop_service_packets:
			return "drop_service_packets";
		case service_counter::drop_service_bytes:
			return "drop_service_bytes";
		case service_counter::drop_blacklist:
			return "drop_blacklist";
		case service_counter::service_bucket_overflow:
			return "service_bucket_overflow";
		case service_counter::failed_local_pool_allocation:
			return "failed_local_pool_allocation";
		case service_counter::failed_local_pool_search_ack:
			return "failed_local_pool_search_ack";
		case service_counter::failed_local_pool_search_syn_ack:
			return "failed_local_pool_search_syn_ack";
		case service_counter::failed_answer_service_syn_ack:
			return "failed_answer_service_syn_ack";
		case service_counter::ignored_size_update_detections:
			return "ignored_size_update_detections";
		case service_counter::failed_check_syn_cookie:
			return "failed_check_syn_cookie";
		case service_counter::failed_search_client_service_ack:
			return "failed_search_client_service_ack";
		case service_counter::new_connections:
			return "new_connections";
		case service_counter::new_syn_connections:
			return "new_syn_connections";
		case service_counter::success_check_syn_cookie:
			return "success_check_syn_cookie";
		case service_counter::service_syn_ack_count:
			return "service_syn_ack_count";
		case service_counter::error_service_config_timestamps:
			return "error_service_config_timestamps";
		case service_counter::error_service_config_sack:
			return "error_service_config_sack";
		case service_counter::error_service_config_mss:
			return "error_service_config_mss";
		case service_counter::ack_without_service_answer:
			return "ack_without_service_answer";
		case service_counter::ack_invalid_ack_number:
			return "ack_invalid_ack_number";
		case service_counter::pkts_with_corrupted_tcp_opts_client:
			return "pkts_with_corrupted_tcp_opts_client";
		case service_counter::pkts_with_corrupted_tcp_opts_service:
			return "pkts_with_corrupted_tcp_opts_service";
		case service_counter::rst_service:
			return "rst_service";
		case service_counter::drop_connection_limit:
			return "drop_connection_limit";
		case service_counter::drop_rate_limit:
			return "drop_rate_limit";
		case service_counter::connection_limiter_new:
			return "connection_limiter_new";
		case service_counter::connection_limiter_remove:
			return "connection_limiter_remove";
		case service_counter::connection_limiter_overflow:
			return "connection_limiter_overflow";
		case service_counter::rate_limiter_overflow:
			return "rate_limiter_overflow";
		case service_counter::size:
			return "unknown";
	}

	return "unknown";
}

}
