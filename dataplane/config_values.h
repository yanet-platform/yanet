#pragma once

#include "common/config.release.h"
#include <cstdint>
#include <nlohmann/json.hpp>

struct FragmentationConfig
{
	uint64_t size = 1024;
	uint64_t timeout_first = 32;
	uint64_t timeout_last = 16;
	uint64_t packets_per_flow = 64;
};

struct ConfigValues
{
	uint64_t port_rx_queue_size = 4096;
	uint64_t port_tx_queue_size = 4096;
	uint64_t ring_highPriority_size = 64;
	uint64_t ring_normalPriority_size = 256;
	uint64_t ring_lowPriority_size = 64;
	uint64_t ring_toFreePackets_size = 64;
	uint64_t ring_log_size = 1024;
	FragmentationConfig fragmentation;
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

inline void from_json(const nlohmann::json& j, ConfigValues& cfg)
{
	cfg.port_rx_queue_size = j.value("port_rx_queue_size", cfg.port_rx_queue_size);
	cfg.port_tx_queue_size = j.value("port_tx_queue_size", cfg.port_tx_queue_size);
	cfg.ring_highPriority_size = j.value("ring_highPriority_size", cfg.ring_highPriority_size);
	cfg.ring_normalPriority_size = j.value("ring_normalPriority_size", cfg.ring_normalPriority_size);
	cfg.ring_lowPriority_size = j.value("ring_lowPriority_size", cfg.ring_lowPriority_size);
	cfg.ring_toFreePackets_size = j.value("ring_toFreePackets_size", cfg.ring_toFreePackets_size);
	cfg.ring_log_size = j.value("ring_log_size", cfg.ring_log_size);
	cfg.fragmentation.size = j.value("fragmentation_size", cfg.fragmentation.size);
	cfg.fragmentation.timeout_first = j.value("fragmentation_timeout_first", cfg.fragmentation.timeout_first);
	cfg.fragmentation.timeout_last = j.value("fragmentation_timeout_last", cfg.fragmentation.timeout_last);
	cfg.fragmentation.packets_per_flow = j.value("fragmentation_packets_per_flow", cfg.fragmentation.packets_per_flow);

	{
		/*
		  The decoding order of four options bellow is important. The first one
		  is more common and sets a timeout value for any tcp session whereas
		  three following aloow one to set timeouts more precissely basing on
		  the last processed tcp session packet flags. So if any of flag-based
		  options is ommitted the more common option should be applied.
		*/
		cfg.stateful_firewall_tcp_timeout = j.value("stateful_firewall_tcp_timeout", cfg.stateful_firewall_tcp_timeout);
		cfg.stateful_firewall_tcp_syn_timeout = j.value("stateful_firewall_tcp_syn_timeout", cfg.stateful_firewall_tcp_timeout);
		cfg.stateful_firewall_tcp_syn_ack_timeout = j.value("stateful_firewall_tcp_syn_ack_timeout", cfg.stateful_firewall_tcp_syn_timeout);
		cfg.stateful_firewall_tcp_fin_timeout = j.value("stateful_firewall_tcp_fin_timeout", cfg.stateful_firewall_tcp_timeout);
	}

	cfg.stateful_firewall_udp_timeout = j.value("stateful_firewall_udp_timeout", cfg.stateful_firewall_udp_timeout);
	cfg.stateful_firewall_other_protocols_timeout = j.value("stateful_firewall_other_protocols_timeout", cfg.stateful_firewall_other_protocols_timeout);
	cfg.gc_step = j.value("gc_step", cfg.gc_step);
	cfg.sample_gc_step = j.value("sample_gc_step", cfg.sample_gc_step);
	cfg.acl_states4_ht_size = j.value("acl_states4_ht_size", cfg.acl_states4_ht_size);
	cfg.acl_states6_ht_size = j.value("acl_states6_ht_size", cfg.acl_states6_ht_size);
	cfg.master_mempool_size = j.value("master_mempool_size", cfg.master_mempool_size);
	cfg.nat64stateful_states_size = j.value("nat64stateful_states_size", cfg.nat64stateful_states_size);
	cfg.kernel_interface_queue_size = j.value("kernel_interface_queue_size", cfg.kernel_interface_queue_size);
	cfg.balancer_state_ht_size = j.value("balancer_state_ht_size", cfg.balancer_state_ht_size);
	cfg.tsc_active_state = j.value("tsc_active_state", cfg.tsc_active_state);

	{
		/*
		  The decoding order of four options bellow is important. The first one
		  is more common and sets a timeout value for any tcp session whereas
		  three following aloow one to set timeouts more precissely basing on
		  the last processed tcp session packet flags. So if any of flag-based
		  options is ommitted the more common option should be applied.
		*/
		cfg.balancer_tcp_timeout = j.value("balancer_tcp_timeout", cfg.balancer_tcp_timeout);
		cfg.balancer_tcp_syn_timeout = j.value("balancer_tcp_syn_timeout", cfg.balancer_tcp_timeout);
		cfg.balancer_tcp_syn_ack_timeout = j.value("balancer_tcp_syn_ack_timeout", cfg.balancer_tcp_syn_timeout);
		cfg.balancer_tcp_fin_timeout = j.value("balancer_tcp_fin_timeout", cfg.balancer_tcp_timeout);
	}

	cfg.balancer_udp_timeout = j.value("balancer_udp_timeout", cfg.balancer_udp_timeout);
	cfg.balancer_other_protocols_timeout = j.value("balancer_other_protocols_timeout", cfg.balancer_other_protocols_timeout);
	cfg.neighbor_ht_size = j.value("neighbor_ht_size", cfg.neighbor_ht_size);
}
