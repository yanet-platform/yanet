#pragma once

#include<common/config.h>
#include <nlohmann/json.hpp>

#include <cstdint>

struct ConfigValues {
	uint64_t port_rx_queue_size = 4096;
	uint64_t port_tx_queue_size = 4096;
	uint64_t ring_highPriority_size = 64;
	uint64_t ring_normalPriority_size = 256;
	uint64_t ring_lowPriority_size = 64;
	uint64_t ring_toFreePackets_size = 64;
	uint64_t ring_log_size = 1024;
	uint64_t fragmentation_size = 1024;
	uint64_t fragmentation_timeout_first = 32;
	uint64_t fragmentation_timeout_last = 16;
	uint64_t fragmentation_packets_per_flow = 64;
	uint64_t stateful_firewall_tcp_timeout = 120;
	uint64_t stateful_firewall_tcp_syn_timeout = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
	uint64_t stateful_firewall_tcp_syn_ack_timeout = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
	uint64_t stateful_firewall_tcp_fin_timeout = YANET_CONFIG_STATE_TIMEOUT_DEFAULT;
	uint64_t stateful_firewall_udp_timeout = 30;
	uint64_t stateful_firewall_other_protocols_timeout = 16;
	uint64_t gc_step = 8;
	uint64_t sample_gc_step = 512;
	uint64_t acl_states4_ht_size = YANET_CONFIG_ACL_STATES4_HT_SIZE;
	uint64_t acl_states6_ht_size = YANET_CONFIG_ACL_STATES6_HT_SIZE;
	uint64_t master_mempool_size = 8192;
	uint64_t nat64stateful_states_size = YANET_CONFIG_NAT64STATEFUL_HT_SIZE;
	uint64_t kernel_interface_queue_size = YANET_CONFIG_KERNEL_INTERFACE_QUEUE_SIZE;
	uint64_t balancer_state_ht_size = YANET_CONFIG_BALANCER_STATE_HT_SIZE;
	uint64_t tsc_active_state = YANET_CONFIG_TSC_ACTIVE_STATE;
	uint64_t balancer_tcp_timeout = YANET_CONFIG_BALANCER_STATE_TIMEOUT_DEFAULT;
	uint64_t balancer_tcp_syn_timeout = YANET_CONFIG_BALANCER_STATE_TIMEOUT_DEFAULT;
	uint64_t balancer_tcp_syn_ack_timeout = YANET_CONFIG_BALANCER_STATE_TIMEOUT_DEFAULT;
	uint64_t balancer_tcp_fin_timeout = YANET_CONFIG_BALANCER_STATE_TIMEOUT_DEFAULT;
	uint64_t balancer_udp_timeout = YANET_CONFIG_BALANCER_STATE_TIMEOUT_DEFAULT;
	uint64_t balancer_other_protocols_timeout = YANET_CONFIG_BALANCER_STATE_TIMEOUT_DEFAULT;
	uint64_t neighbor_ht_size = 64 * 1024;
};

inline void from_json(const nlohmann::json& j, ConfigValues& cfg) {
	#define from_json_if_exists(some_key) \
	if (j.find(#some_key) != j.end()) {\
		cfg.some_key = j[#some_key];\
	};
	#define from_json_dependent(specific_key, general_key) cfg.specific_key = j.value(#specific_key, cfg.general_key);

	from_json_if_exists(port_rx_queue_size)
	from_json_if_exists(port_tx_queue_size)
	from_json_if_exists(ring_highPriority_size)
	from_json_if_exists(ring_normalPriority_size)
	from_json_if_exists(ring_lowPriority_size)
	from_json_if_exists(ring_toFreePackets_size)
	from_json_if_exists(ring_log_size)
	from_json_if_exists(fragmentation_size)
	from_json_if_exists(fragmentation_timeout_first)
	from_json_if_exists(fragmentation_timeout_last)
	from_json_if_exists(fragmentation_packets_per_flow)

	{
		/*
		  The decoding order of four options bellow is important. The first one
		  is more common and sets a timeout value for any tcp session whereas
		  three following aloow one to set timeouts more precissely basing on
		  the last processed tcp session packet flags. So if any of flag-based
		  options is ommitted the more common option should be applied.
		*/
		from_json_if_exists(stateful_firewall_tcp_timeout)
		from_json_dependent(stateful_firewall_tcp_syn_timeout, stateful_firewall_tcp_timeout)
		from_json_dependent(stateful_firewall_tcp_syn_ack_timeout, stateful_firewall_tcp_syn_timeout)
		from_json_dependent(stateful_firewall_tcp_fin_timeout, stateful_firewall_tcp_timeout)
	}

	from_json_if_exists(stateful_firewall_udp_timeout)
	from_json_if_exists(stateful_firewall_other_protocols_timeout)
	from_json_if_exists(gc_step)
	from_json_if_exists(sample_gc_step)
	from_json_if_exists(acl_states4_ht_size)
	from_json_if_exists(acl_states6_ht_size)
	from_json_if_exists(master_mempool_size)
	from_json_if_exists(nat64stateful_states_size)
	from_json_if_exists(kernel_interface_queue_size)
	from_json_if_exists(balancer_state_ht_size)
	from_json_if_exists(tsc_active_state)

	{
		/*
		  The decoding order of four options bellow is important. The first one
		  is more common and sets a timeout value for any tcp session whereas
		  three following aloow one to set timeouts more precissely basing on
		  the last processed tcp session packet flags. So if any of flag-based
		  options is ommitted the more common option should be applied.
		*/
		from_json_if_exists(balancer_tcp_timeout)
		from_json_dependent(balancer_tcp_syn_timeout, balancer_tcp_timeout)
		from_json_dependent(balancer_tcp_syn_ack_timeout, balancer_tcp_syn_timeout)
		from_json_dependent(balancer_tcp_fin_timeout, balancer_tcp_timeout)
	}

	from_json_if_exists(balancer_udp_timeout)
	from_json_if_exists(balancer_other_protocols_timeout)
	from_json_if_exists(neighbor_ht_size)

	#undef from_json_dependent
	#undef from_json_if_exists
}

