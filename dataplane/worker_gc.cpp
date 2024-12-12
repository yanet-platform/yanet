#include <rte_errno.h>
#include <rte_ethdev.h>

#include "common/counters.h"
#include "common/fallback.h"
#include "dataplane/globalbase.h"
#include "dataplane/sdpserver.h"
#include "dataplane/worker_gc.h"

worker_gc_t::worker_gc_t(const ConfigValues& cfg, const PortToSocketArray& pts, SamplersVector&& samplers) :
        mempool(nullptr),
        core_id(-1),
        socket_id(-1),
        iteration(0),
        current_base_id(0),
        local_base_id(0),
        toSlowWorker_(toSlowWorkers_.begin(), toSlowWorkers_.end()),
        port_id_to_socket_id{pts},
        samplers_{samplers},
        callback_id(0),
        gc_step{static_cast<uint32_t>(cfg.gc_step)},
        sample_gc_step{static_cast<uint32_t>(cfg.sample_gc_step)}
{
}

worker_gc_t::~worker_gc_t()
{
	if (mempool)
	{
		rte_mempool_free(mempool);
	}

	for (auto& ring : toSlowWorkers_)
	{
		ring.Destroy();
	}

	for (auto& ring : toFree_)
	{
		ring.Destroy();
	}
}

eResult worker_gc_t::init(const tCoreId& core_id,
                          const tSocketId& socket_id,
                          const dataplane::base::permanently& base_permanently,
                          const dataplane::base::generation& base)
{
	this->core_id = core_id;
	this->socket_id = socket_id;
	this->base_permanently = base_permanently;
	this->bases[local_base_id] = base;
	this->bases[local_base_id ^ 1] = base;

	mempool = rte_mempool_create(("wgc" + std::to_string(core_id)).data(),
	                             CONFIG_YADECAP_MBUFS_COUNT + 3 * CONFIG_YADECAP_PORTS_SIZE * CONFIG_YADECAP_MBUFS_BURST_SIZE,
	                             CONFIG_YADECAP_MBUF_SIZE,
	                             0,
	                             sizeof(struct rte_pktmbuf_pool_private),
	                             rte_pktmbuf_pool_init,
	                             nullptr,
	                             rte_pktmbuf_init,
	                             nullptr,
	                             rte_socket_id(),
	                             0); ///< multi-producers, multi-consumers
	if (!mempool)
	{
		YADECAP_LOG_ERROR("rte_mempool_create(): %s [%u]\n", rte_strerror(rte_errno), rte_errno);
		return eResult::errorInitMempool;
	}

	return eResult::success;
}

[[nodiscard]] std::optional<dpdk::RingConn<rte_mbuf*>> worker_gc_t::RegisterSlowWorker(const std::string& name,
                                                                                       unsigned int capacity,
                                                                                       unsigned int capacity_to_free)
{
	if (toSlowWorkers_.Full() || toFree_.Full())
	{
		YANET_LOG_ERROR("Trying to assign to many workers to garbage collector on core %d\n", core_id);
		return std::nullopt;
	}
	auto rs = dpdk::Ring<rte_mbuf*>::Make(
	        "r_gc" + std::to_string(socket_id) + "_to_" + name,
	        capacity,
	        socket_id,
	        RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (!rs)
	{
		return std::nullopt;
	}

	auto rf = dpdk::Ring<rte_mbuf*>::Make(
	        "r_tfmb_gc" + std::to_string(socket_id) + "_from_" + name,
	        capacity_to_free,
	        socket_id,
	        RING_F_SP_ENQ | RING_F_SC_DEQ);

	if (!rf)
	{
		rs.value().Destroy();
		return std::nullopt;
	}

	toSlowWorkers_.push_back(rs.value());
	toFree_.push_back(rf.value());

	toSlowWorker_ = {toSlowWorkers_.begin(), toSlowWorkers_.end()};
	return dpdk::RingConn<rte_mbuf*>{std::move(rs.value()), std::move(rf.value())};
}

void worker_gc_t::start()
{
	thread();
}

void worker_gc_t::run_on_this_thread(const std::function<bool()>& callback)
{
	unsigned int callback_id = 0;

	{
		std::lock_guard<std::mutex> guard(callbacks_mutex);
		callback_id = this->callback_id++;
		callbacks.try_emplace(callback_id, callback);
	}

	for (;;)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds{5});

		{
			std::lock_guard<std::mutex> guard(callbacks_mutex);
			if (!exist(callbacks, callback_id))
			{
				return;
			}
		}
	}
}

void worker_gc_t::limits(common::idp::limits::response& response) const
{
	auto* globalbase_atomic = base_permanently.globalBaseAtomic;

	globalbase_atomic->updater.balancer_state.limits(response, "balancer.ht");
	globalbase_atomic->updater.nat64stateful_lan_state.limits(response, "nat64stateful.lan.state.ht");
	globalbase_atomic->updater.nat64stateful_wan_state.limits(response, "nat64stateful.wan.state.ht");
	globalbase_atomic->updater.fw4_state.limits(response, "acl.state.v4.ht");
	globalbase_atomic->updater.fw6_state.limits(response, "acl.state.v6.ht");
}

void worker_gc_t::FillMetadataWorkerCounters(common::sdp::MetadataWorkerGc& metadata)
{
	metadata.size = 0;
	metadata.start_counters = common::sdp::SdrSever::GetStartData(YANET_CONFIG_COUNTERS_SIZE * sizeof(uint64_t), metadata.size);
	metadata.start_stats = common::sdp::SdrSever::GetStartData(sizeof(common::worker_gc::stats_t), metadata.size);

	// stats
	static_assert(std::is_trivially_destructible<common::worker_gc::stats_t>::value, "invalid struct destructible");
	std::map<std::string, uint64_t> counters_stats;
	counters_stats["broken_packets"] = offsetof(common::worker_gc::stats_t, broken_packets);
	counters_stats["drop_packets"] = offsetof(common::worker_gc::stats_t, drop_packets);
	counters_stats["ring_to_slowworker_packets"] = offsetof(common::worker_gc::stats_t, ring_to_slowworker_packets);
	counters_stats["ring_to_slowworker_drops"] = offsetof(common::worker_gc::stats_t, ring_to_slowworker_drops);
	counters_stats["fwsync_multicast_egress_packets"] = offsetof(common::worker_gc::stats_t, fwsync_multicast_egress_packets);
	counters_stats["fwsync_multicast_egress_drops"] = offsetof(common::worker_gc::stats_t, fwsync_multicast_egress_drops);
	counters_stats["fwsync_unicast_egress_packets"] = offsetof(common::worker_gc::stats_t, fwsync_unicast_egress_packets);
	counters_stats["fwsync_unicast_egress_drops"] = offsetof(common::worker_gc::stats_t, fwsync_unicast_egress_drops);
	counters_stats["drop_samples"] = offsetof(common::worker_gc::stats_t, drop_samples);
	counters_stats["balancer_state_insert_failed"] = offsetof(common::worker_gc::stats_t, balancer_state_insert_failed);
	counters_stats["balancer_state_insert_done"] = offsetof(common::worker_gc::stats_t, balancer_state_insert_done);

	for (const auto& iter : counters_stats)
	{
		metadata.counter_positions[iter.first] = (metadata.start_stats + iter.second) / sizeof(uint64_t);
	}
}

void worker_gc_t::SetBufferForCounters(void* buffer, const common::sdp::MetadataWorkerGc& metadata)
{
	counters = utils::ShiftBuffer<uint64_t*>(buffer, metadata.start_counters);
	stats = utils::ShiftBuffer<common::worker_gc::stats_t*>(buffer, metadata.start_stats);
}

YANET_INLINE_NEVER void worker_gc_t::thread()
{
	for (;;)
	{
		local_base_id = current_base_id;
		handle();
		iteration++;

#ifdef CONFIG_YADECAP_AUTOTEST
		std::this_thread::sleep_for(std::chrono::microseconds{1});
#endif // CONFIG_YADECAP_AUTOTEST
	}
}

void worker_gc_t::handle()
{
	current_time = base_permanently.globalBaseAtomic->currentTime;

	handle_nat64stateful_gc();
	handle_balancer_gc();
	handle_acl_gc();
	handle_acl_sync();
	handle_callbacks();
	handle_free_mbuf();
	handle_samples();
}

void worker_gc_t::handle_nat64stateful_gc()
{
	const auto& base = bases[local_base_id & 1];
	auto* globalbase_atomic = base_permanently.globalBaseAtomic;

	for (auto iter : globalbase_atomic->updater.nat64stateful_wan_state.gc(nat64stateful_wan_state_gc.offset, gc_step))
	{
		iter.lock();
		if (!iter.is_valid())
		{
			iter.unlock();
			continue;
		}

		correct_timestamp(iter.value()->timestamp_last_packet);
		auto flags = iter.value()->flags;
		auto wan_key = *iter.key();
		auto wan_value = *iter.value();
		iter.unlock();

		nat64stateful_wan_state_gc.valid_keys++;

		if ((wan_key.port_destination & base_permanently.nat64stateful_numa_reverse_mask) != base_permanently.nat64stateful_numa_id)
		{
			/// this state created on another numa
			continue;
		}

		uint16_t last_seen = calc_last_seen(wan_value.timestamp_last_packet);

		const auto& nat64stateful = base.globalBase->nat64statefuls[wan_key.nat64stateful_id];

		/// check other wan tables
		for (auto globalbase_atomic : base_permanently.globalBaseAtomics)
		{
			if (globalbase_atomic == base_permanently.globalBaseAtomic)
			{
				continue;
			}
			else if (globalbase_atomic == nullptr)
			{
				break;
			}

			dataplane::globalBase::nat64stateful_wan_value* wan_value_lookup = nullptr;
			dataplane::spinlock_nonrecursive_t* wan_locker = nullptr;
			globalbase_atomic->nat64stateful_wan_state->lookup(wan_key, wan_value_lookup, wan_locker);
			if (wan_value_lookup)
			{
				correct_timestamp(wan_value_lookup->timestamp_last_packet);
				last_seen = RTE_MIN(last_seen, calc_last_seen(wan_value_lookup->timestamp_last_packet));
				flags |= wan_value_lookup->flags;
			}
			wan_locker->unlock();
		}

		dataplane::globalBase::nat64stateful_lan_key lan_key;
		lan_key.nat64stateful_id = wan_key.nat64stateful_id;
		lan_key.proto = wan_key.proto;
		lan_key.ipv6_source = wan_value.ipv6_destination;
		lan_key.ipv6_destination = wan_value.ipv6_source;
		lan_key.ipv6_destination.mapped_ipv4_address = wan_key.ipv4_source;
		lan_key.port_source = wan_value.port_destination;
		lan_key.port_destination = wan_key.port_source;

		/// check lan tables
		for (auto globalbase_atomic : base_permanently.globalBaseAtomics)
		{
			if (globalbase_atomic == nullptr)
			{
				break;
			}

			dataplane::globalBase::nat64stateful_lan_value* lan_value_lookup = nullptr;
			dataplane::spinlock_nonrecursive_t* lan_locker = nullptr;
			globalbase_atomic->nat64stateful_lan_state->lookup(lan_key, lan_value_lookup, lan_locker);
			if (lan_value_lookup)
			{
				correct_timestamp(lan_value_lookup->timestamp_last_packet);
				last_seen = RTE_MIN(last_seen, calc_last_seen(lan_value_lookup->timestamp_last_packet));
				flags |= lan_value_lookup->flags;
			}
			lan_locker->unlock();
		}

		uint16_t timeout = nat64stateful.state_timeout.other;
		if (wan_key.proto == IPPROTO_TCP)
		{
			if (flags & (TCP_FIN_FLAG | TCP_RST_FLAG))
			{
				timeout = nat64stateful.state_timeout.tcp_fin;
			}
			else if (flags & TCP_ACK_FLAG)
			{
				timeout = nat64stateful.state_timeout.tcp_ack;
			}
			else
			{
				timeout = nat64stateful.state_timeout.tcp_syn;
			}
		}
		else if (wan_key.proto == IPPROTO_UDP)
		{
			timeout = nat64stateful.state_timeout.udp;
		}
		else if (wan_key.proto == IPPROTO_ICMPV6)
		{
			timeout = nat64stateful.state_timeout.icmp;
		}

		if (last_seen > timeout)
		{
			nat64stateful_remove_state(lan_key, wan_key);
		}
	}

	if (nat64stateful_wan_state_gc.offset == 0)
	{
		nat64stateful_wan_state_gc.iterations++;
	}

	/// for calc stats only
	for (auto iter : globalbase_atomic->updater.nat64stateful_lan_state.gc(nat64stateful_lan_state_gc.offset, gc_step))
	{
		iter.lock();
		if (!iter.is_valid())
		{
			iter.unlock();
			continue;
		}
		iter.unlock();

		nat64stateful_lan_state_gc.valid_keys++;
	}

	if (nat64stateful_lan_state_gc.offset == 0)
	{
		nat64stateful_lan_state_gc.iterations++;
	}
}

void worker_gc_t::handle_balancer_gc()
{
	const auto& base = bases[local_base_id & 1];
	auto* globalbase_atomic = base_permanently.globalBaseAtomic;

	/// @todo: skip if balancer disabled

	for (auto iter : globalbase_atomic->updater.balancer_state.gc(globalbase_atomic->balancer_state_gc.offset, gc_step))
	{
		if (iter.is_valid())
		{
			/// sync
			iter.lock();
			iter.unlock();

			globalbase_atomic->balancer_state_gc.valid_keys++;

			/// balancer service connections
			{
				common::idp::balancer_service_connections::service_key_t key;
				auto& [balancer_id, virtual_ip, proto, virtual_port] = key;

				balancer_id = iter.key()->balancer_id;
				proto = iter.key()->protocol;
				virtual_port = rte_be_to_cpu_16(iter.key()->port_destination);

				if (iter.key()->addr_type == 4)
				{
					virtual_ip = common::ipv4_address_t(rte_be_to_cpu_32(iter.key()->ip_destination.mapped_ipv4_address.address));
				}
				else
				{
					virtual_ip = common::ipv6_address_t(iter.key()->ip_destination.bytes);
				}

				++balancer_service_connections.next()[key];
			}

			/// balancer real connections
			{
				common::idp::balancer_real_connections::real_key_t key;
				auto& [balancer_id, virtual_ip, proto, virtual_port, real_ip, real_port] = key;

				balancer_id = iter.key()->balancer_id;
				proto = iter.key()->protocol;
				virtual_port = rte_be_to_cpu_16(iter.key()->port_destination);
				real_port = virtual_port; ///< @todo

				if (iter.key()->addr_type == 4)
				{
					virtual_ip = common::ipv4_address_t(rte_be_to_cpu_32(iter.key()->ip_destination.mapped_ipv4_address.address));
				}
				else
				{
					virtual_ip = common::ipv6_address_t(iter.key()->ip_destination.bytes);
				}

				const auto& real_from_base = base.globalBase->balancer_reals[iter.value()->real_unordered_id];
				const auto real_ip_version = (real_from_base.flags & YANET_BALANCER_FLAG_DST_IPV6) ? 6 : 4;
				real_ip = common::ip_address_t(real_ip_version, real_from_base.destination.bytes);

				++balancer_real_connections.next()[key];
			}

			iter.lock();
			if (iter.value()->timestamp_gc != iter.value()->timestamp_last_packet)
			{
				iter.value()->timestamp_gc = iter.value()->timestamp_last_packet;
				auto value = *iter.value();
				iter.unlock();

				for (auto globalbase_atomic_other : base_permanently.globalBaseAtomics)
				{
					if (globalbase_atomic_other == nullptr)
					{
						break;
					}

					if (globalbase_atomic == globalbase_atomic_other)
					{
						continue;
					}

					bool saved = true;
					bool updated = false;

					dataplane::globalBase::balancer_state_value_t* ht_value = nullptr;
					dataplane::spinlock_nonrecursive_t* locker = nullptr;
					uint32_t old_real_id = 0;

					uint32_t hash = globalbase_atomic_other->balancer_state->lookup(*iter.key(), ht_value, locker);
					if (ht_value)
					{
						old_real_id = ht_value->real_unordered_id;
						*ht_value = value;
						updated = true;
					}
					else
					{
						saved = globalbase_atomic_other->balancer_state->insert(hash, *iter.key(), value);
					}

					locker->unlock();

					if (saved)
					{
						stats->balancer_state_insert_done++;
						const auto& real_from_base = base.globalBase->balancer_reals[value.real_unordered_id];
						if (updated)
						{
							if (old_real_id != value.real_unordered_id)
							{
								const auto& old_real_from_base = base.globalBase->balancer_reals[old_real_id];
								++counters[old_real_from_base.counter_id + (tCounterId)balancer::gc_real_counter::sessions_destroyed];
								++counters[real_from_base.counter_id + (tCounterId)balancer::gc_real_counter::sessions_created];
							}
						}
						else
						{
							++counters[real_from_base.counter_id + (tCounterId)balancer::gc_real_counter::sessions_created];
						}
					}
					else
					{
						stats->balancer_state_insert_failed++;
					}
				}

				iter.lock();
			}
			auto* value = iter.value();
			if (is_timeout(value->timestamp_last_packet, value->state_timeout))
			{
				const auto& real_from_base = base.globalBase->balancer_reals[value->real_unordered_id];
				++counters[real_from_base.counter_id + (tCounterId)balancer::gc_real_counter::sessions_destroyed];
				iter.unset_valid();
			}
			iter.unlock();
		}
	}

	if (globalbase_atomic->balancer_state_gc.offset == 0)
	{
		balancer_service_connections.switch_generation();
		balancer_real_connections.switch_generation();
		balancer_state_stats.switch_generation();
		globalbase_atomic->balancer_state_gc.iterations++;
	}
}

void worker_gc_t::handle_acl_gc()
{
	auto& globalbase_atomic = base_permanently.globalBaseAtomic;

	fw_state_insert_stack.clear();
	fw_state_remove_stack.clear();

	for (auto iter : globalbase_atomic->updater.fw4_state.gc(fw4_state_gc.offset, gc_step))
	{
		if (iter.is_valid())
		{
			iter.lock();
			auto key = *iter.key();
			auto value = *iter.value();
			iter.unlock();

			fw4_state_gc.valid_keys++;

			common::idp::getFWState::key_t fw_key(std::uint8_t(key.proto), {rte_be_to_cpu_32(key.src_addr.address)}, {rte_be_to_cpu_32(key.dst_addr.address)}, key.src_port, key.dst_port);
			fw_state_insert_stack.emplace_back(
			        fw_key,
			        std::make_tuple(
			                static_cast<std::uint8_t>(value.owner),
			                value.tcp.pack(),
			                current_time - value.last_seen,
			                value.packets_backward,
			                value.packets_forward));

			if (value.type == dataplane::globalBase::fw_state_type::tcp)
			{
				if (is_timeout(value.last_seen, value.state_timeout))
				{
					fw_state_remove_stack.emplace_back(fw_key);

					iter.lock();
					iter.unset_valid();
				}
				else if (current_time - value.last_sync >= globalbase_atomic->fw_state_config.sync_timeout &&
				         value.packets_since_last_sync > 0)
				{
					auto frame = dataplane::globalBase::fw_state_sync_frame_t::from_state_key(key);
					frame.flags = value.tcp.pack();
					fw_state_sync_events.emplace(
					        frame,
					        value.acl_id);

					iter.lock();
					iter.value()->last_sync = current_time;
					iter.value()->packets_since_last_sync = 0;
				}
				else
				{
					iter.lock();
				}
			}
			else if (value.type == dataplane::globalBase::fw_state_type::udp)
			{
				if (is_timeout(value.last_seen, value.state_timeout))
				{
					fw_state_remove_stack.emplace_back(fw_key);

					iter.lock();
					iter.unset_valid();
				}
				else if (current_time - value.last_sync >= globalbase_atomic->fw_state_config.sync_timeout &&
				         value.packets_since_last_sync > 0)
				{
					fw_state_sync_events.emplace(
					        dataplane::globalBase::fw_state_sync_frame_t::from_state_key(key),
					        value.acl_id);

					iter.lock();
					iter.value()->last_sync = current_time;
					iter.value()->packets_since_last_sync = 0;
				}
				else
				{
					iter.lock();
				}
			}
			else
			{
				if (is_timeout(value.last_seen, value.state_timeout))
				{
					fw_state_remove_stack.emplace_back(fw_key);

					iter.lock();
					iter.unset_valid();
				}
				else if (current_time - value.last_sync >= globalbase_atomic->fw_state_config.sync_timeout &&
				         value.packets_since_last_sync > 0)
				{
					fw_state_sync_events.emplace(
					        dataplane::globalBase::fw_state_sync_frame_t::from_state_key(key),
					        value.acl_id);

					iter.lock();
					iter.value()->last_sync = current_time;
					iter.value()->packets_since_last_sync = 0;
				}
				else
				{
					iter.lock();
				}
			}

			iter.unlock();
		}
		else
		{
			// The entry is invalid, likely due to a call to clearFWState().
			iter.lock();
			auto key = *iter.key();
			iter.unlock();

			common::idp::getFWState::key_t fw_key(
			        std::uint8_t(key.proto),
			        {rte_be_to_cpu_32(key.src_addr.address)},
			        {rte_be_to_cpu_32(key.dst_addr.address)},
			        key.src_port,
			        key.dst_port);

			fw_state_remove_stack.emplace_back(fw_key);
		}
	}

	if (fw4_state_gc.offset == 0)
	{
		fw4_state_gc.iterations++;
	}

	for (auto iter : globalbase_atomic->updater.fw6_state.gc(fw6_state_gc.offset, gc_step))
	{
		if (iter.is_valid())
		{
			iter.lock();
			auto key = *iter.key();
			auto value = *iter.value();
			iter.unlock();

			fw6_state_gc.valid_keys++;

			common::idp::getFWState::key_t fw_key(std::uint8_t(key.proto), {key.src_addr.bytes}, {key.dst_addr.bytes}, key.src_port, key.dst_port);
			fw_state_insert_stack.emplace_back(
			        fw_key,
			        std::make_tuple(
			                static_cast<std::uint8_t>(value.owner),
			                value.tcp.pack(),
			                current_time - value.last_seen,
			                value.packets_backward,
			                value.packets_forward));

			if (value.type == dataplane::globalBase::fw_state_type::tcp)
			{
				if (is_timeout(value.last_seen, value.state_timeout))
				{
					fw_state_remove_stack.emplace_back(fw_key);

					iter.lock();
					iter.unset_valid();
				}
				else if (current_time - value.last_sync >= globalbase_atomic->fw_state_config.sync_timeout &&
				         value.packets_since_last_sync > 0)
				{
					auto frame = dataplane::globalBase::fw_state_sync_frame_t::from_state_key(key);
					frame.flags = value.tcp.pack();
					fw_state_sync_events.emplace(
					        frame,
					        value.acl_id);

					iter.lock();
					iter.value()->last_sync = current_time;
					iter.value()->packets_since_last_sync = 0;
				}
				else
				{
					iter.lock();
				}
			}
			else if (value.type == dataplane::globalBase::fw_state_type::udp)
			{
				if (is_timeout(value.last_seen, value.state_timeout))
				{
					fw_state_remove_stack.emplace_back(fw_key);

					iter.lock();
					iter.unset_valid();
				}
				else if (current_time - value.last_sync >= globalbase_atomic->fw_state_config.sync_timeout &&
				         value.packets_since_last_sync > 0)
				{
					fw_state_sync_events.emplace(
					        dataplane::globalBase::fw_state_sync_frame_t::from_state_key(key),
					        value.acl_id);

					iter.lock();
					iter.value()->last_sync = current_time;
					iter.value()->packets_since_last_sync = 0;
				}
				else
				{
					iter.lock();
				}
			}
			else
			{
				if (is_timeout(value.last_seen, value.state_timeout))
				{
					fw_state_remove_stack.emplace_back(fw_key);

					iter.lock();
					iter.unset_valid();
				}
				else if (current_time - value.last_sync >= globalbase_atomic->fw_state_config.sync_timeout &&
				         value.packets_since_last_sync > 0)
				{
					fw_state_sync_events.emplace(
					        dataplane::globalBase::fw_state_sync_frame_t::from_state_key(key),
					        value.acl_id);

					iter.lock();
					iter.value()->last_sync = current_time;
					iter.value()->packets_since_last_sync = 0;
				}
				else
				{
					iter.lock();
				}
			}

			iter.unlock();
		}
		else
		{
			// The entry is invalid, likely due to a call to clearFWState().
			iter.lock();
			auto key = *iter.key();
			iter.unlock();

			common::idp::getFWState::key_t fw_key(
			        std::uint8_t(key.proto),
			        {key.src_addr.bytes},
			        {key.dst_addr.bytes},
			        key.src_port,
			        key.dst_port);

			fw_state_remove_stack.emplace_back(fw_key);
		}
	}

	if (fw6_state_gc.offset == 0)
	{
		fw6_state_gc.iterations++;
	}

	// Update fwstate table.
	{
		std::lock_guard<std::mutex> guard(fw_state_mutex);

		for (const auto& [key, value] : fw_state_insert_stack)
		{
			fw_state[key] = value;
		}

		for (const auto& key : fw_state_remove_stack)
		{
			fw_state.erase(key);
		}
	}
}

void worker_gc_t::handle_acl_sync()
{
	const auto& base = bases[local_base_id & 1];

	while (!fw_state_sync_events.empty())
	{
		rte_mbuf* mbuf = rte_pktmbuf_alloc(mempool);
		if (mbuf == nullptr)
		{
			// No luck here. Try at the next iteration.
			break;
		}

		/// @todo: init metadata

		const auto& [frame, aclId] = fw_state_sync_events.front();

		constexpr uint16_t payload_offset = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr);
		rte_pktmbuf_append(mbuf, payload_offset + sizeof(dataplane::globalBase::fw_state_sync_frame_t));

		dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
		metadata->flow.data.aclId = aclId;

		// We're only filling the payload here.
		// Other headers will be set in the slow worker before emitting.
		void* payload = rte_pktmbuf_mtod_offset(mbuf, void*, payload_offset);
		memcpy(payload, (void*)&frame, sizeof(dataplane::globalBase::fw_state_sync_frame_t));

		{
			const auto& fw_state_config = base.globalBase->fw_state_sync_configs[metadata->flow.data.aclId];

			metadata->network_headerType = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
			metadata->network_headerOffset = sizeof(rte_ether_hdr) + sizeof(rte_vlan_hdr);
			metadata->transport_headerType = IPPROTO_UDP;
			metadata->transport_headerOffset = metadata->network_headerOffset + sizeof(rte_ipv6_hdr);

			generic_rte_ether_hdr* ethernetHeader = rte_pktmbuf_mtod(mbuf, generic_rte_ether_hdr*);
			ethernetHeader->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN);
			rte_ether_addr_copy(&fw_state_config.ether_address_destination, &ethernetHeader->dst_addr);

			rte_vlan_hdr* vlanHeader = rte_pktmbuf_mtod_offset(mbuf, rte_vlan_hdr*, sizeof(rte_ether_hdr));
			vlanHeader->eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

			rte_ipv6_hdr* ipv6Header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv6_hdr*, metadata->network_headerOffset);
			ipv6Header->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
			ipv6Header->payload_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + sizeof(dataplane::globalBase::fw_state_sync_frame_t));
			ipv6Header->proto = IPPROTO_UDP;
			ipv6Header->hop_limits = 64;
			memcpy(ipv6Header->src_addr, fw_state_config.ipv6_address_source.bytes, 16);
			memcpy(ipv6Header->dst_addr, fw_state_config.ipv6_address_multicast.bytes, 16);

			rte_udp_hdr* udpHeader = rte_pktmbuf_mtod_offset(mbuf, rte_udp_hdr*, metadata->network_headerOffset + sizeof(rte_ipv6_hdr));
			udpHeader->src_port = fw_state_config.port_multicast; // IPFW reuses the same port for both src and dst.
			udpHeader->dst_port = fw_state_config.port_multicast;
			udpHeader->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + sizeof(dataplane::globalBase::fw_state_sync_frame_t));
			udpHeader->dgram_cksum = 0;
			udpHeader->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6Header, udpHeader);

			// Iterate for all interested ports.
			for (unsigned int port_id = 0; port_id < fw_state_config.flows_size; port_id++)
			{
				const auto& flow = fw_state_config.flows[port_id];

				if (flow.type == common::globalBase::eFlowType::logicalPort_egress)
				{
					const auto& port_id = base.globalBase->logicalPorts[flow.data.logicalPortId].portId;
					const auto& port_socket_id = port_id_to_socket_id[port_id];

					if (socket_id != port_socket_id)
					{
						continue;
					}
				}

				rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool);
				if (mbuf_clone == nullptr)
				{
					stats->fwsync_multicast_egress_drops++;
					continue;
				}

				*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);

				memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
				       rte_pktmbuf_mtod(mbuf, char*),
				       mbuf->data_len);
				mbuf_clone->data_len = mbuf->data_len;
				mbuf_clone->pkt_len = mbuf->pkt_len;

				stats->fwsync_multicast_egress_packets++;
				utils::SetFlow(mbuf_clone, flow);
				SendToSlowWorker(mbuf_clone);
			}

			if (!fw_state_config.ipv6_address_unicast.empty())
			{
				memcpy(ipv6Header->src_addr, fw_state_config.ipv6_address_unicast_source.bytes, 16);
				memcpy(ipv6Header->dst_addr, fw_state_config.ipv6_address_unicast.bytes, 16);
				udpHeader->src_port = fw_state_config.port_unicast;
				udpHeader->dst_port = fw_state_config.port_unicast;
				udpHeader->dgram_cksum = 0;
				udpHeader->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6Header, udpHeader);

				rte_mbuf* mbuf_clone = rte_pktmbuf_alloc(mempool);
				if (mbuf_clone == nullptr)
				{
					stats->fwsync_unicast_egress_drops++;
				}
				else
				{
					*YADECAP_METADATA(mbuf_clone) = *YADECAP_METADATA(mbuf);

					memcpy(rte_pktmbuf_mtod(mbuf_clone, char*),
					       rte_pktmbuf_mtod(mbuf, char*),
					       mbuf->data_len);
					mbuf_clone->data_len = mbuf->data_len;
					mbuf_clone->pkt_len = mbuf->pkt_len;

					stats->fwsync_unicast_egress_packets++;
					utils::SetFlow(mbuf_clone, fw_state_config.ingress_flow);
					SendToSlowWorker(mbuf_clone);
				}
			}
		}

		rte_pktmbuf_free(mbuf);

		fw_state_sync_events.pop();
	}
}

void worker_gc_t::handle_callbacks()
{
	if (iteration % 1024 == 0)
	{
		std::lock_guard<std::mutex> guard(callbacks_mutex);
		callbacks_current = callbacks;
	}

	std::vector<unsigned int> callback_ids_remove;

	for (const auto& [callback_id, callback] : callbacks_current)
	{
		bool result = callback();
		if (result)
		{
			callback_ids_remove.emplace_back(callback_id);
		}
	}

	if (callback_ids_remove.size())
	{
		for (const auto callback_id : callback_ids_remove)
		{
			callbacks_current.erase(callback_id);
		}

		{
			std::lock_guard<std::mutex> guard(callbacks_mutex);
			for (const auto callback_id : callback_ids_remove)
			{
				callbacks.erase(callback_id);
			}
		}
	}
}

void worker_gc_t::handle_free_mbuf()
{
	rte_mbuf* mbufs[CONFIG_YADECAP_MBUFS_BURST_SIZE];
	unsigned int mbufs_count = 0;

	for (auto& ring : toFree_)
	{
		mbufs_count = ring.DequeueBurstSC(mbufs);
		rte_pktmbuf_free_bulk(mbufs, mbufs_count);
	}
}

inline bool worker_gc_t::is_timeout(const uint32_t timestamp,
                                    const uint32_t timeout)
{
	return ((uint32_t)(current_time - timestamp) > timeout);
}

inline void worker_gc_t::correct_timestamp(uint16_t& timestamp,
                                           const uint16_t last_seen_max)
{
	auto last_seen = (uint16_t)(current_time - timestamp);
	if (last_seen > last_seen_max)
	{
		timestamp = (uint16_t)(current_time - last_seen_max);
	}
}

inline uint16_t worker_gc_t::calc_last_seen(const uint16_t timestamp)
{
	return (uint16_t)(current_time - timestamp);
}

void worker_gc_t::nat64stateful_remove_state(const dataplane::globalBase::nat64stateful_lan_key& lan_key,
                                             const dataplane::globalBase::nat64stateful_wan_key& wan_key)
{
	/// remove on other numas
	for (auto globalbase_atomic : base_permanently.globalBaseAtomics)
	{
		if (globalbase_atomic == base_permanently.globalBaseAtomic)
		{
			continue;
		}
		else if (globalbase_atomic == nullptr)
		{
			break;
		}

		globalbase_atomic->nat64stateful_lan_state->remove(lan_key);
		globalbase_atomic->nat64stateful_wan_state->remove(wan_key);
	}

	/// remove on same numa
	{
		auto* globalbase_atomic = base_permanently.globalBaseAtomic;
		globalbase_atomic->nat64stateful_lan_state->remove(lan_key);
		globalbase_atomic->nat64stateful_wan_state->remove(wan_key); ///< must be deleted last!
	}
}

void worker_gc_t::SendToSlowWorker(rte_mbuf* mbuf)
{
	if (toSlowWorker_->EnqueueSP(mbuf))
	{
		stats->ring_to_slowworker_drops++;
		rte_pktmbuf_free(mbuf);
	}
	else
	{
		stats->ring_to_slowworker_packets++;
	}
}

void worker_gc_t::handle_samples()
{
	if ((iteration + 1) % sample_gc_step != 0)
	{
		return;
	}

	std::lock_guard<std::mutex> guard(samples_mutex);

	for (auto sampler : samplers_)
	{
		sampler->visit6([this](auto& sample) {
			if (samples.size() < YANET_CONFIG_SAMPLES_SIZE * 8)
			{
				samples.emplace(sample.proto, sample.in_logicalport_id, sample.out_logicalport_id, sample.src_port, sample.dst_port, sample.src_addr.bytes, sample.dst_addr.bytes);
			}
			else
			{
				stats->drop_samples++;
			}
		});
		sampler->visit4([this](auto& sample) {
			if (samples.size() < YANET_CONFIG_SAMPLES_SIZE * 8)
			{
				samples.emplace(sample.proto, sample.in_logicalport_id, sample.out_logicalport_id, sample.src_port, sample.dst_port, rte_be_to_cpu_32(sample.src_addr.address), rte_be_to_cpu_32(sample.dst_addr.address));
			}
			else
			{
				stats->drop_samples++;
			}
		});
		sampler->clear();
	}

	if (samples_current_base_id != current_base_id)
	{
		// config changed, aclId may be invalid now
		stats->drop_samples += samples.size();
		samples.clear();
		samples_current_base_id = current_base_id;
	}
}

void worker_gc_t::nat64stateful_state(const common::idp::nat64stateful_state::request& request,
                                      common::idp::nat64stateful_state::response& response)
{
	uint32_t offset = 0;
	run_on_this_thread([&]() {
		const auto& [filter_nat64stateful_id] = request;
		auto& globalbase_atomic = base_permanently.globalBaseAtomic;

		for (auto iter : globalbase_atomic->updater.nat64stateful_wan_state.range(offset, 64))
		{
			iter.lock();
			if (!iter.is_valid())
			{
				iter.unlock();
				continue;
			}

			if ((iter.key()->port_destination & base_permanently.nat64stateful_numa_reverse_mask) != base_permanently.nat64stateful_numa_id)
			{
				/// this state created on another numa
				iter.unlock();
				continue;
			}

			auto wan_key = *iter.key();
			auto wan_value = *iter.value();
			iter.unlock();

			if (filter_nat64stateful_id &&
			    wan_key.nat64stateful_id != *filter_nat64stateful_id)
			{
				continue;
			}

			uint32_t lan_flags = 0;
			uint32_t wan_flags = wan_value.flags;
			uint16_t lan_last_seen = YANET_CONFIG_STATE_TIMEOUT_MAX;
			uint16_t wan_last_seen = calc_last_seen(wan_value.timestamp_last_packet);

			/// check other wan tables
			for (auto globalbase_atomic : base_permanently.globalBaseAtomics)
			{
				if (globalbase_atomic == base_permanently.globalBaseAtomic)
				{
					continue;
				}
				else if (globalbase_atomic == nullptr)
				{
					break;
				}

				dataplane::globalBase::nat64stateful_wan_value* wan_value_lookup = nullptr;
				dataplane::spinlock_nonrecursive_t* wan_locker = nullptr;
				globalbase_atomic->nat64stateful_wan_state->lookup(wan_key, wan_value_lookup, wan_locker);
				if (wan_value_lookup)
				{
					wan_last_seen = RTE_MIN(wan_last_seen, calc_last_seen(wan_value_lookup->timestamp_last_packet));
					wan_flags |= wan_value_lookup->flags;
				}
				wan_locker->unlock();
			}

			dataplane::globalBase::nat64stateful_lan_key lan_key;
			lan_key.nat64stateful_id = wan_key.nat64stateful_id;
			lan_key.proto = wan_key.proto;
			lan_key.ipv6_source = wan_value.ipv6_destination;
			lan_key.ipv6_destination = wan_value.ipv6_source;
			lan_key.ipv6_destination.mapped_ipv4_address = wan_key.ipv4_source;
			lan_key.port_source = wan_value.port_destination;
			lan_key.port_destination = wan_key.port_source;

			/// check lan tables
			for (auto globalbase_atomic : base_permanently.globalBaseAtomics)
			{
				if (globalbase_atomic == nullptr)
				{
					break;
				}

				dataplane::globalBase::nat64stateful_lan_value* lan_value_lookup = nullptr;
				dataplane::spinlock_nonrecursive_t* lan_locker = nullptr;
				globalbase_atomic->nat64stateful_lan_state->lookup(lan_key, lan_value_lookup, lan_locker);
				if (lan_value_lookup)
				{
					lan_last_seen = RTE_MIN(lan_last_seen, calc_last_seen(lan_value_lookup->timestamp_last_packet));
					lan_flags |= lan_value_lookup->flags;
				}
				lan_locker->unlock();
			}

			std::optional<uint16_t> lan_last_seen_opt;
			if (lan_last_seen < YANET_CONFIG_STATE_TIMEOUT_MAX)
			{
				lan_last_seen_opt = lan_last_seen;
			}

			std::optional<uint16_t> wan_last_seen_opt;
			if (wan_last_seen < YANET_CONFIG_STATE_TIMEOUT_MAX)
			{
				wan_last_seen_opt = wan_last_seen;
			}

			response.emplace_back((uint32_t)lan_key.nat64stateful_id,
			                      lan_key.proto,
			                      lan_key.ipv6_source.bytes,
			                      lan_key.ipv6_destination.bytes,
			                      rte_be_to_cpu_16(lan_key.port_source),
			                      rte_be_to_cpu_16(lan_key.port_destination),
			                      rte_be_to_cpu_32(wan_key.ipv4_destination.address),
			                      rte_be_to_cpu_16(wan_key.port_destination),
			                      lan_flags,
			                      wan_flags,
			                      std::move(lan_last_seen_opt),
			                      std::move(wan_last_seen_opt));
		}

		if (offset != 0)
		{
			return false;
		}

		return true;
	});
}

void worker_gc_t::balancer_state_clear()
{
	uint32_t offset = 0;
	run_on_this_thread([&]() {
		auto& globalbase_atomic = base_permanently.globalBaseAtomic;

		for (auto iter : globalbase_atomic->updater.balancer_state.range(offset, 64))
		{
			iter.lock();
			if (iter.is_valid())
			{
				iter.unset_valid();
			}
			iter.unlock();
		}

		if (offset != 0)
		{
			return false;
		}

		return true;
	});
}
