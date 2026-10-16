#include <gtest/gtest.h>
#include <rte_ring.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "balancer_gc_fixture.h"
#include "common/counters.h"
#include "dataplane/balancer_gc.h"

namespace
{
namespace gb = dataplane::globalBase;

template<typename Value, typename Table, typename Key>
std::optional<Value> lookup(Table& table, const Key& key)
{
	Value* value;
	dataplane::spinlock_nonrecursive_t* locker;
	table.lookup(key, value, locker);
	std::optional<Value> result;
	if (value)
	{
		result = *value;
	}
	locker->unlock();
	return result;
}

class BalancerGcTest : public ::testing::Test
{
protected:
	balancer_gc_test::Harness harness;
};

TEST_F(BalancerGcTest, HandlePreservesBalancerReplicationAndCallbackProgress)
{
	constexpr unsigned ring_size = 16;
	const auto ring_bytes = rte_ring_get_memsize(ring_size);
	ASSERT_GT(ring_bytes, 0);
	std::unique_ptr<void, decltype(&std::free)> ring_memory(
	        std::aligned_alloc(RTE_CACHE_LINE_SIZE, ring_bytes), &std::free);
	ASSERT_NE(nullptr, ring_memory);
	auto* ring = static_cast<rte_ring*>(ring_memory.get());
	ASSERT_EQ(0, rte_ring_init(ring, "worker-gc-test", ring_size, RING_F_SP_ENQ | RING_F_SC_DEQ));
	auto& worker = *harness.worker;
	worker.ring_to_free_mbuf = ring;
	worker.current_time = 0; // handle() must load the atomic base's clock.
	balancer_gc_test::State replica(*harness.dataplane, 1);
	worker.base_permanently.globalBaseAtomics[1] = replica.atomic.get();
	worker.base_permanently.activeNumaNodesCount = 2;

	gb::balancer_state_key_t key{};
	key.balancer_id = 1;
	key.protocol = IPPROTO_TCP;
	key.addr_type = 4;
	key.ip_source.mapped_ipv4_address.address = rte_cpu_to_be_32(0xC0000201u);
	key.ip_destination.mapped_ipv4_address.address = rte_cpu_to_be_32(0xC6336401u);
	key.port_source = rte_cpu_to_be_16(12345);
	key.port_destination = rte_cpu_to_be_16(443);
	const gb::balancer_state_value_t value{0, 999, 1000, 999, 10};
	ASSERT_TRUE(harness.state.balancer.pointer->insert_or_update(key, value));
	harness.generation->balancer_reals[0].destination.mapped_ipv4_address.address = rte_cpu_to_be_32(0xC0000202u);

	unsigned callback_calls = 0;
	worker.callbacks.emplace(0, [&]() { return ++callback_calls == 3; });
	for (uint32_t scanned = 8; scanned <= balancer_gc_test::State::slots; scanned += 8)
	{
		harness.tick();
		const auto offset = scanned % balancer_gc_test::State::slots;
		EXPECT_EQ(1000u, worker.current_time);
		EXPECT_EQ(offset, worker.nat64stateful_wan_state_gc.offset);
		EXPECT_EQ(offset, worker.nat64stateful_lan_state_gc.offset);
		EXPECT_EQ(offset, worker.fw4_state_gc.offset);
		EXPECT_EQ(offset, worker.fw6_state_gc.offset);
		EXPECT_EQ(offset, harness.state.atomic->balancer_state_gc.offset);
	}
	EXPECT_EQ(3u, callback_calls);
	EXPECT_TRUE(worker.callbacks.empty());
	EXPECT_TRUE(worker.callbacks_current.empty());
	EXPECT_EQ(1u, harness.state.atomic->balancer_state_gc.iterations);
	EXPECT_EQ(1u, harness.state.atomic->balancer_state_gc.valid_keys);
	EXPECT_EQ(1u, worker.stats.balancer_state_insert_done);
	EXPECT_EQ(0u, worker.stats.balancer_state_insert_failed);
	EXPECT_EQ(0u, rte_ring_count(ring));
	EXPECT_TRUE(worker.fw_state.empty());

	const auto copied = lookup<gb::balancer_state_value_t>(*replica.balancer.pointer, key);
	ASSERT_TRUE(copied.has_value());
	EXPECT_EQ(value.real_unordered_id, copied->real_unordered_id);
	EXPECT_EQ(value.timestamp_create, copied->timestamp_create);
	EXPECT_EQ(value.timestamp_last_packet, copied->timestamp_last_packet);
	EXPECT_EQ(value.timestamp_last_packet, copied->timestamp_gc);
	EXPECT_EQ(value.state_timeout, copied->state_timeout);
	const auto& services = worker.balancer_service_connections.current();
	const auto& reals = worker.balancer_real_connections.current();
	ASSERT_EQ(1u, services.size());
	ASSERT_EQ(1u, reals.size());
	EXPECT_EQ(1u, services.begin()->second);
	EXPECT_EQ(1u, reals.begin()->second);
}

using real_connections = common::idp::balancer_real_connections::connections;
using service_connections = common::idp::balancer_service_connections::connections;

service_connections reference_services(const real_connections& reals)
{
	service_connections services;
	for (const auto& [key, count] : reals)
	{
		services[{std::get<0>(key), std::get<1>(key), std::get<2>(key), std::optional<uint16_t>{std::get<3>(key)}}] += count;
	}
	return services;
}

real_connections::key_type projection_key(uint32_t index, bool one_service = false)
{
	const auto service = one_service ? 0 : index % 7;
	const common::ip_address_t vip = service % 2
	                                         ? common::ip_address_t("2001:db8::" + std::to_string(service + 1))
	                                         : common::ip_address_t(common::ipv4_address_t(0xC0000201u + service));
	const common::ip_address_t backend = index % 2
	                                             ? common::ip_address_t("2001:db8:1::" + std::to_string(index + 1))
	                                             : common::ip_address_t(common::ipv4_address_t(0x0A000001u + index));
	return {1u + service % 3, vip, uint8_t(service % 2 ? IPPROTO_UDP : IPPROTO_TCP), uint16_t(service % 3 ? 80 + service : 0), backend, uint16_t(1000 + index)};
}

TEST(BalancerGcProjectionTest, BoundedChunksMatchReferenceForMixedKeys)
{
	constexpr auto budget = worker_gc_t::balancer_projection_budget;
	static_assert(budget == 32);
	for (const uint32_t rows : {0u, 1u, 31u, 32u, 33u, 64u, 65u})
	{
		SCOPED_TRACE(rows);
		real_connections reals;
		for (uint32_t i = 0; i < rows; ++i)
		{
			reals.emplace(projection_key(i), i + 1);
		}
		const service_connections::key_type sentinel{0, common::ip_address_t("192.0.2.254"), IPPROTO_UDP, uint16_t(0)};
		service_connections services{{sentinel, 17}};
		const auto unchanged = services;
		EXPECT_EQ(reals.cbegin(), dataplane::balancer_gc::accumulate_service_counts(reals.cbegin(), reals.cend(), services, 0));
		EXPECT_EQ(unchanged, services);

		auto cursor = reals.cbegin();
		do
		{
			const auto first = cursor;
			const auto remaining = std::distance(first, reals.cend());
			cursor = dataplane::balancer_gc::accumulate_service_counts(first, reals.cend(), services, budget);
			EXPECT_EQ(std::min<std::ptrdiff_t>(budget, remaining), std::distance(first, cursor));
			const real_connections consumed(reals.cbegin(), cursor);
			auto expected = reference_services(consumed);
			expected.emplace(sentinel, 17);
			EXPECT_EQ(expected, services);
		} while (cursor != reals.cend());
		for (const auto& service : services)
		{
			EXPECT_TRUE(std::get<3>(service.first).has_value());
		}
	}
}

TEST(BalancerGcProjectionTest, OneServiceGroupHonorsBudgetAndWrapsCounters)
{
	real_connections reals;
	for (uint32_t i = 0; i < 65; ++i)
	{
		reals.emplace(projection_key(i, true), 1);
	}
	reals.begin()->second = std::numeric_limits<uint32_t>::max();
	service_connections services;
	auto cursor = reals.cbegin();
	constexpr std::array<uint32_t, 3> totals{30, 62, 63};
	constexpr std::array<uint32_t, 3> rows{32, 32, 1};
	for (size_t chunk = 0; chunk < rows.size(); ++chunk)
	{
		const auto first = cursor;
		cursor = dataplane::balancer_gc::accumulate_service_counts(first, reals.cend(), services, 32);
		EXPECT_EQ(rows[chunk], std::distance(first, cursor));
		ASSERT_EQ(1u, services.size());
		const auto& port = std::get<3>(services.begin()->first);
		ASSERT_TRUE(port.has_value());
		EXPECT_EQ(0u, *port); // L3/zero ports must remain engaged, not nullopt.
		EXPECT_EQ(totals[chunk], services.begin()->second);
	}
	EXPECT_EQ(reals.cend(), cursor);
	EXPECT_EQ(reference_services(reals), services);
}

class BalancerGcProjectionWorkerTest : public BalancerGcTest
{
protected:
	std::unique_ptr<void, decltype(&std::free)> ring_memory{nullptr, &std::free};
	std::vector<gb::balancer_state_key_t> keys;
	real_connections expected_reals;

	void SetUp() override
	{
		const auto bytes = rte_ring_get_memsize(16);
		ASSERT_GT(bytes, 0);
		ring_memory.reset(std::aligned_alloc(RTE_CACHE_LINE_SIZE, bytes));
		ASSERT_NE(nullptr, ring_memory);
		auto* ring = static_cast<rte_ring*>(ring_memory.get());
		ASSERT_EQ(0, rte_ring_init(ring, "balancer-projection-test", 16, RING_F_SP_ENQ | RING_F_SC_DEQ));
		harness.worker->ring_to_free_mbuf = ring;
		ASSERT_FALSE(harness.worker->balancer_next_real_entry.has_value());
	}

	void populate(uint32_t count, uint32_t epoch = 0, bool expire_first = false)
	{
		keys.clear();
		expected_reals.clear();
		auto& worker = *harness.worker;
		auto& base = *worker.bases[worker.current_base_id & 1].globalBase;
		for (uint32_t i = 0; i < count; ++i)
		{
			const auto service = i % 4;
			gb::balancer_state_key_t key{};
			key.balancer_id = 1 + service / 2;
			key.protocol = service % 2 ? IPPROTO_UDP : IPPROTO_TCP;
			key.l3_balancing = service == 0;
			key.addr_type = 4;
			key.ip_source.mapped_ipv4_address.address = rte_cpu_to_be_32(0xC0000201u + i);
			key.ip_destination.mapped_ipv4_address.address = rte_cpu_to_be_32(0xC6336401u + service);
			key.port_destination = rte_cpu_to_be_16(service ? 80 + service : 0);
			bool found = false;
			for (uint32_t port = 0; port <= 0xFFFFu; ++port)
			{
				auto candidate = key;
				candidate.port_source = rte_cpu_to_be_16(static_cast<uint16_t>(port));
				const auto hash = dataplane::calculate_hash_xxh32(candidate);
				if ((hash & 1u) == i / 32 && ((hash >> 1) & 31u) == i % 32)
				{
					key = candidate;
					found = true;
					break;
				}
			}
			ASSERT_TRUE(found) << i;
			auto& real = base.balancer_reals[i];
			real = {};
			real.destination.mapped_ipv4_address.address = rte_cpu_to_be_32(0x0A000001u + epoch * 256 + i);
			real.counter_id = 128 + i * 8;
			const auto last_packet = worker.current_time - (expire_first && i == 0 ? 11 : 0);
			const gb::balancer_state_value_t value{i, last_packet, last_packet, last_packet, 10};
			ASSERT_TRUE(harness.state.balancer.pointer->insert_or_update(key, value));
			keys.push_back(key);
			const auto port = rte_be_to_cpu_16(key.port_destination);
			++expected_reals[{key.balancer_id, common::ip_address_t(4, key.ip_destination.bytes), key.protocol, port, common::ip_address_t(4, real.destination.bytes), port}];
		}
	}

	void clear_states()
	{
		// Equivalent to the serialized balancer_state_clear callback, without waiting
		// on run_on_this_thread from the same GC thread.
		uint32_t offset = 0;
		for (auto iter : harness.state.atomic->updater.balancer_state.range(offset, balancer_gc_test::State::slots))
		{
			iter.lock();
			if (iter.is_valid())
			{
				iter.unset_valid();
			}
			iter.unlock();
		}
	}
};

TEST_F(BalancerGcProjectionWorkerTest, PendingProjectionDelaysPublicationWithoutRescanning)
{
	ASSERT_NO_FATAL_FAILURE(populate(40, 0, true));
	auto& worker = *harness.worker;
	const real_connections sentinel_reals{{projection_key(1000), 99}};
	const auto sentinel_services = reference_services(sentinel_reals);
	worker.balancer_real_connections.next() = sentinel_reals;
	worker.balancer_real_connections.switch_generation();
	worker.balancer_service_connections.next() = sentinel_services;
	worker.balancer_service_connections.switch_generation();
	worker.balancer_state_stats.next().valid_keys = 1234;
	worker.balancer_state_stats.switch_generation();
	unsigned callback_calls = 0;
	unsigned pending_callbacks = 0;
	worker.callbacks.emplace(0, [&]() {
		++callback_calls;
		pending_callbacks += worker.balancer_next_real_entry.has_value();
		return callback_calls == 9;
	});
	for (unsigned batch = 0; batch < 8; ++batch)
	{
		harness.tick();
		EXPECT_EQ(sentinel_reals, worker.balancer_real_connections.current());
		EXPECT_EQ(sentinel_services, worker.balancer_service_connections.current());
		EXPECT_EQ(1234u, worker.balancer_state_stats.current().valid_keys);
		EXPECT_EQ(0u, harness.state.atomic->balancer_state_gc.iterations);
	}
	ASSERT_TRUE(worker.balancer_next_real_entry.has_value());
	EXPECT_EQ(0u, harness.state.atomic->balancer_state_gc.offset);
	EXPECT_EQ(40u, harness.state.atomic->balancer_state_gc.valid_keys);
	EXPECT_EQ(expected_reals, worker.balancer_real_connections.next());
	const auto& frozen = worker.balancer_real_connections.next();
	EXPECT_EQ(32, std::distance(frozen.cbegin(), *worker.balancer_next_real_entry));
	const real_connections consumed(frozen.cbegin(), *worker.balancer_next_real_entry);
	EXPECT_EQ(reference_services(consumed), worker.balancer_service_connections.next());
	EXPECT_FALSE(lookup<gb::balancer_state_value_t>(*harness.state.balancer.pointer, keys[0]).has_value());
	constexpr auto expired_counter = 128 + static_cast<tCounterId>(balancer::gc_real_counter::sessions_destroyed);
	EXPECT_EQ(1u, worker.counters[expired_counter]);

	harness.tick();
	EXPECT_FALSE(worker.balancer_next_real_entry.has_value());
	EXPECT_EQ(expected_reals, worker.balancer_real_connections.current());
	EXPECT_EQ(reference_services(expected_reals), worker.balancer_service_connections.current());
	EXPECT_TRUE(worker.balancer_real_connections.next().empty());
	EXPECT_TRUE(worker.balancer_service_connections.next().empty());
	EXPECT_EQ(0u, worker.balancer_state_stats.current().valid_keys);
	EXPECT_EQ(1u, harness.state.atomic->balancer_state_gc.iterations);
	EXPECT_EQ(0u, harness.state.atomic->balancer_state_gc.offset);
	EXPECT_EQ(40u, harness.state.atomic->balancer_state_gc.valid_keys);
	EXPECT_EQ(1u, worker.counters[expired_counter]);
	EXPECT_EQ(0u, worker.stats.balancer_state_insert_done);
	EXPECT_EQ(9u, callback_calls);
	EXPECT_EQ(1u, pending_callbacks);
	EXPECT_EQ(8u, worker.nat64stateful_wan_state_gc.offset);
	EXPECT_EQ(8u, worker.nat64stateful_lan_state_gc.offset);
	EXPECT_EQ(8u, worker.fw4_state_gc.offset);
	EXPECT_EQ(8u, worker.fw6_state_gc.offset);
}

TEST_F(BalancerGcProjectionWorkerTest, ClearAndBaseChangePreservePendingSnapshot)
{
	ASSERT_NO_FATAL_FAILURE(populate(40));
	const auto old_reals = expected_reals;
	auto& worker = *harness.worker;
	auto replacement = std::make_unique<gb::generation>(harness.dataplane.get(), 0);
	replacement->decap_enabled = 0;
	replacement->nat64stateful_enabled = 1;
	replacement->nat64stateless_enabled = 0;
	replacement->nat46clat_enabled = 0;
	replacement->balancer_enabled = 1;
	replacement->acl_egress_enabled = 0;
	replacement->sampler_enabled = 0;
	replacement->tun64_enabled = 0;
	replacement->early_decap_enabled = 0;
	replacement->serial = 1;
	worker.bases[1].globalBase = replacement.get();
	unsigned clear_calls = 0;
	worker.callbacks.emplace(0, [&]() {
		if (!worker.balancer_next_real_entry)
		{
			return false;
		}
		clear_states();
		worker.current_base_id = 1;
		// Change backend metadata for all captured IDs before the remaining chunk.
		for (uint32_t i = 0; i < 40; ++i)
		{
			replacement->balancer_reals[i] = harness.generation->balancer_reals[i];
			replacement->balancer_reals[i].destination.mapped_ipv4_address.address = rte_cpu_to_be_32(0x0A000101u + i);
		}
		populate(3, 1);
		++clear_calls;
		return true;
	});
	for (unsigned batch = 0; batch < 8; ++batch)
	{
		harness.tick();
	}
	ASSERT_EQ(1u, clear_calls);
	ASSERT_TRUE(worker.balancer_next_real_entry.has_value());
	EXPECT_EQ(old_reals, worker.balancer_real_connections.next());
	EXPECT_TRUE(worker.balancer_real_connections.current().empty());
	EXPECT_EQ(0u, harness.state.atomic->balancer_state_gc.iterations);
	const auto new_reals = expected_reals;
	harness.tick();
	EXPECT_EQ(1u, worker.local_base_id);
	EXPECT_FALSE(worker.balancer_next_real_entry.has_value());
	EXPECT_EQ(old_reals, worker.balancer_real_connections.current());
	EXPECT_EQ(reference_services(old_reals), worker.balancer_service_connections.current());
	EXPECT_EQ(40u, harness.state.atomic->balancer_state_gc.valid_keys);
	EXPECT_EQ(1u, harness.state.atomic->balancer_state_gc.iterations);

	for (unsigned batch = 0; batch < 8; ++batch)
	{
		harness.tick();
	}
	EXPECT_EQ(new_reals, worker.balancer_real_connections.current());
	EXPECT_EQ(reference_services(new_reals), worker.balancer_service_connections.current());
	EXPECT_FALSE(worker.balancer_next_real_entry.has_value());
	EXPECT_EQ(43u, harness.state.atomic->balancer_state_gc.valid_keys);
	EXPECT_EQ(2u, harness.state.atomic->balancer_state_gc.iterations);
	clear_states();
	for (unsigned batch = 0; batch < 8; ++batch)
	{
		harness.tick();
	}
	EXPECT_TRUE(worker.balancer_real_connections.current().empty());
	EXPECT_TRUE(worker.balancer_service_connections.current().empty());
	EXPECT_FALSE(worker.balancer_next_real_entry.has_value());
	EXPECT_EQ(43u, harness.state.atomic->balancer_state_gc.valid_keys);
	EXPECT_EQ(3u, harness.state.atomic->balancer_state_gc.iterations);
}
}
