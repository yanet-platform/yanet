#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <new>
#include <optional>
#include <type_traits>
#include <vector>

#include "../globalbase.h"
#include "../hashtable.h"
#include "../type.h"

namespace
{

TEST(HashtableTest, Basic)
{
	dataplane::hashtable_chain_t<int, int, 128, 128, 4, 4> t;

	int* v;
	int k = 1;
	t.lookup(&k, &v, 1);
	EXPECT_EQ(nullptr, v);

	EXPECT_EQ(true, t.insert(1, 1));
	EXPECT_EQ(true, t.insert(1, 1));

	t.lookup(&k, &v, 1);
	EXPECT_EQ(1, *v);

	t.clear();
	t.lookup(&k, &v, 1);
	EXPECT_EQ(nullptr, v);
}

TEST(HashtableTest, Extended)
{
	dataplane::hashtable_chain_spinlock_t<int, int, 128, 128, 2, 4> t;

	for (int k = 0; k < 512; ++k)
	{
		if ((k % 7) && (k % 11))
		{
			t.insert(k, k);
		}
	}

	bool ok = true;

	for (int k = 0; k < 512; ++k)
	{
		int* v;
		dataplane::spinlock_t* locker;

		t.lookup(k, v, locker);
		if ((k % 7) && (k % 11))
		{
			if (v)
			{
				ok &= *v == k;
				locker->unlock();
			}
			else
			{
				ok = false;
				break;
			}
		}
		else
		{
			if (v)
			{
				ok = false;
				break;
			}
		}
	}

	EXPECT_TRUE(ok);
	EXPECT_NE(t.getStats().extendedChunksCount, 0);

	uint32_t from = 0;
	for (auto iter : t.range(from, 8192))
	{
		iter.lock();
		if (iter.isValid())
		{
			int key = *iter.key();
			int value = *iter.value();
			if (key == value &&
			    0 <= value &&
			    value < 512 &&
			    (key % 7) && (key % 11))
			{
				iter.unsetValid();
			}
		}
		iter.gc();
		iter.unlock();
	}

	from = 0;
	for (auto iter : t.range(from, 8192))
	{
		iter.lock();
		iter.gc();
		iter.unlock();
	}

	EXPECT_EQ(t.getStats().extendedChunksCount, 0);
	EXPECT_EQ(t.getStats().pairs, 0);

	for (int k = 0; k < 512; ++k)
	{
		if ((k % 7) && (k % 11))
		{
			t.insert(k, k);
		}
	}

	for (int k = 0; k < 512; ++k)
	{
		if ((k % 7) && (k % 11))
		{
			t.remove(k);
		}
	}

	from = 0;
	for (auto iter : t.range(from, 8192))
	{
		iter.lock();
		iter.gc();
		iter.unlock();
	}

	EXPECT_EQ(t.getStats().extendedChunksCount, 0);
	EXPECT_EQ(t.getStats().pairs, 0);

	for (int k = 0; k < 100500; ++k)
	{
		t.insert(k, k);
	}

	EXPECT_EQ(t.getStats().extendedChunksCount, 128);
	EXPECT_EQ(t.getStats().pairs, 128 * 2 + 128 * 4);

	t.clear();

	EXPECT_EQ(t.getStats().extendedChunksCount, 0);
	EXPECT_EQ(t.getStats().pairs, 0);
}

TEST(hashtable_mod_id32, basic)
{
	using ht_t = dataplane::hashtable_mod_id32<ipv6_address_t,
	                                           128,
	                                           4>;

	ht_t ht;
	ht_t::updater updater;

	const ipv6_address_t key = ipv6_address_t::convert(common::ipv6_address_t("abcd::1234"));
	const uint32_t value1 = 12345u;
	const uint32_t value2 = 12345678u;

	uint32_t hashes[YANET_CONFIG_BURST_SIZE];
	ipv6_address_t keys[YANET_CONFIG_BURST_SIZE];
	uint32_t values[YANET_CONFIG_BURST_SIZE];

	keys[0] = key;

	{
		const auto mask = ht.lookup(hashes, keys, values, 1);
		EXPECT_EQ(0xFFFFFFFE, mask);
		EXPECT_EQ(0x80000000, values[0] & (1u << 31));
	}

	EXPECT_EQ(eResult::success, ht.insert(updater, key, value1));

	{
		const auto mask = ht.lookup(hashes, keys, values, 1);
		EXPECT_EQ(0xFFFFFFFF, mask);
		EXPECT_EQ(value1, values[0]);
	}

	EXPECT_EQ(eResult::success, ht.insert(updater, key, value2));

	{
		const auto mask = ht.lookup(hashes, keys, values, 1);
		EXPECT_EQ(0xFFFFFFFF, mask);
		EXPECT_EQ(value2, values[0]);
	}

	ht.clear();

	{
		const auto mask = ht.lookup(hashes, keys, values, 1);
		EXPECT_EQ(0xFFFFFFFE, mask);
		EXPECT_EQ(0x80000000, values[0] & (1u << 31));
	}
}

TEST(hashtable_mod_id32, burst)
{
	using ht_t = dataplane::hashtable_mod_id32<ipv6_address_t,
	                                           128,
	                                           4>;

	ht_t ht;
	ht_t::updater updater;

	const uint32_t value1 = 12345u;
	const uint32_t value2 = 12345678u;

	uint32_t hashes[YANET_CONFIG_BURST_SIZE];
	ipv6_address_t keys[YANET_CONFIG_BURST_SIZE];
	uint32_t values[YANET_CONFIG_BURST_SIZE];

	for (unsigned int i = 0;
	     i < YANET_CONFIG_BURST_SIZE;
	     i++)
	{
		keys[i] = ipv6_address_t::convert(common::ipv6_address_t("1234:abcd::" + std::to_string(i)));
	}

	{
		const auto mask = ht.lookup(hashes, keys, values, YANET_CONFIG_BURST_SIZE);
		EXPECT_EQ(0, mask);
		for (unsigned int i = 0;
		     i < YANET_CONFIG_BURST_SIZE;
		     i++)
		{
			EXPECT_EQ(0x80000000, values[i] & (1u << 31));
		}
	}

	for (unsigned int i = 0;
	     i < YANET_CONFIG_BURST_SIZE;
	     i++)
	{
		EXPECT_EQ(eResult::success, ht.insert(updater, keys[i], value1));
	}

	{
		const auto mask = ht.lookup(hashes, keys, values, YANET_CONFIG_BURST_SIZE);
		EXPECT_EQ(0xFFFFFFFF, mask);
		for (unsigned int i = 0;
		     i < YANET_CONFIG_BURST_SIZE;
		     i++)
		{
			EXPECT_EQ(value1, values[i]);
		}
	}

	for (unsigned int i = 0;
	     i < YANET_CONFIG_BURST_SIZE;
	     i++)
	{
		EXPECT_EQ(eResult::success, ht.insert(updater, keys[i], value2));
	}

	{
		const auto mask = ht.lookup(hashes, keys, values, YANET_CONFIG_BURST_SIZE);
		EXPECT_EQ(0xFFFFFFFF, mask);
		for (unsigned int i = 0;
		     i < YANET_CONFIG_BURST_SIZE;
		     i++)
		{
			EXPECT_EQ(value2, values[i]);
		}
	}

	ht.clear();

	{
		const auto mask = ht.lookup(hashes, keys, values, YANET_CONFIG_BURST_SIZE);
		EXPECT_EQ(0, mask);
		for (unsigned int i = 0;
		     i < YANET_CONFIG_BURST_SIZE;
		     i++)
		{
			EXPECT_EQ(0x80000000, values[i] & (1u << 31));
		}
	}
}

TEST(hashtable_mod_id32, collision)
{
	using ht_t = dataplane::hashtable_mod_id32<uint32_t,
	                                           64,
	                                           32>;

	ht_t ht;
	ht_t::updater updater;

	uint32_t hashes[YANET_CONFIG_BURST_SIZE];
	uint32_t keys[YANET_CONFIG_BURST_SIZE];
	uint32_t values[YANET_CONFIG_BURST_SIZE];

	for (unsigned int i = 0;
	     i < 64;
	     i++)
	{
		EXPECT_EQ(eResult::success, ht.insert(updater, i, 0x31337 + i));
	}

	EXPECT_EQ(14, updater.longest_chain);
	EXPECT_EQ(64, updater.keys_count);
	EXPECT_EQ(0, updater.insert_failed);
	EXPECT_EQ(0, updater.rewrites);

	for (unsigned int i = 0;
	     i < 64;
	     i++)
	{
		keys[0] = i;
		const auto mask = ht.lookup(hashes, keys, values, 1);
		EXPECT_EQ(0xFFFFFFFF, mask);
		EXPECT_EQ(0x31337 + i, values[0]);
	}

	ht.clear();

	for (unsigned int i = 0;
	     i < 64;
	     i++)
	{
		keys[0] = i;
		const auto mask = ht.lookup(hashes, keys, values, 1);
		EXPECT_EQ(0xFFFFFFFE, mask);
		EXPECT_EQ(0x80000000, values[0] & (1u << 31));
	}
}

TEST(hashtable_mod_spinlock, basic)
{
	dataplane::hashtable_mod_spinlock<ipv6_address_t,
	                                  uint32_t,
	                                  1024,
	                                  4>
	        ht;

	const ipv6_address_t key = ipv6_address_t::convert(common::ipv6_address_t("abcd::1234"));
	const uint32_t value1 = 12345u;
	const uint32_t value2 = 12345678u;

	uint32_t* value;
	dataplane::spinlock_nonrecursive_t* locker;

	{
		const uint32_t hash = ht.lookup(key, value, locker);
		EXPECT_EQ(nullptr, value);
		EXPECT_EQ(true, ht.insert(hash, key, value1));
		locker->unlock();
	}

	{
		ht.lookup(key, value, locker);
		EXPECT_NE(nullptr, value);
		EXPECT_EQ(value1, *value);
		locker->unlock();
	}

	EXPECT_EQ(true, ht.insert_or_update(key, value2));

	{
		ht.lookup(key, value, locker);
		EXPECT_NE(nullptr, value);
		EXPECT_EQ(value2, *value);
		locker->unlock();
	}

	{
		uint32_t offset = 0;
		uint32_t valid_keys = 0;
		for (auto iter : ht.range(offset, 1024))
		{
			if (iter.is_valid())
			{
				iter.lock();
				iter.unset_valid();
				iter.unlock();

				valid_keys++;
			}
		}

		EXPECT_EQ(1, valid_keys);
	}

	{
		ht.lookup(key, value, locker);
		EXPECT_EQ(nullptr, value);
		locker->unlock();
	}

	{
		uint32_t offset = 0;
		uint32_t valid_keys = 0;
		for (auto iter : ht.range(offset, 1024))
		{
			if (iter.is_valid())
			{
				/// sync
				iter.lock();
				iter.unlock();

				valid_keys++;
			}
		}

		EXPECT_EQ(0, valid_keys);
	}
}

TEST(hashtable_mod_spinlock, collision)
{
	dataplane::hashtable_mod_spinlock<uint32_t,
	                                  uint32_t,
	                                  64,
	                                  32>
	        ht;

	uint32_t* value;
	dataplane::spinlock_nonrecursive_t* locker;

	for (unsigned int i = 0;
	     i < 64;
	     i++)
	{
		const uint32_t hash = ht.lookup(i, value, locker);
		EXPECT_EQ(nullptr, value);
		EXPECT_EQ(true, ht.insert(hash, i, 0x31337 + i));
		locker->unlock();
	}

	for (unsigned int i = 64;
	     i < 128;
	     i++)
	{
		const uint32_t hash = ht.lookup(i, value, locker);
		EXPECT_EQ(nullptr, value);
		EXPECT_EQ(false, ht.insert(hash, i, 0x31337 + i));
		locker->unlock();
	}

	for (unsigned int i = 0;
	     i < 64;
	     i++)
	{
		ht.lookup(i, value, locker);
		EXPECT_NE(nullptr, value);
		EXPECT_EQ(0x31337 + i, *value);
		locker->unlock();
	}

	for (unsigned int i = 64;
	     i < 128;
	     i++)
	{
		ht.lookup(i, value, locker);
		EXPECT_EQ(nullptr, value);
		locker->unlock();
	}

	{
		uint32_t offset = 0;
		uint32_t valid_keys = 0;
		for (auto iter : ht.range(offset, 64))
		{
			if (iter.is_valid())
			{
				/// sync
				iter.lock();
				iter.unset_valid();
				iter.unlock();

				valid_keys++;
			}
		}

		EXPECT_EQ(64, valid_keys);
	}

	for (unsigned int i = 0;
	     i < 64;
	     i++)
	{
		ht.lookup(i, value, locker);
		EXPECT_EQ(nullptr, value);
		locker->unlock();
	}
}

using balancer_state_ht = dataplane::globalBase::balancer::state_ht;
using balancer_state_key_t = dataplane::globalBase::balancer_state_key_t;
using balancer_state_value_t = dataplane::globalBase::balancer_state_value_t;

static_assert(std::is_same_v<balancer_state_ht,
                             dataplane::hashtable_mod_spinlock_dynamic<balancer_state_key_t,
                                                                       balancer_state_value_t,
                                                                       32,
                                                                       dataplane::calculate_hash_xxh32<balancer_state_key_t>>>);
static_assert(balancer_state_ht::valid_mask_full == 0xFFFFFFFFu);

class BalancerStateHashtableTest : public ::testing::Test
{
protected:
	static constexpr uint32_t total_size = 64;
	std::unique_ptr<char[]> storage;
	balancer_state_ht* ht = nullptr;
	balancer_state_ht::updater updater;
	std::vector<balancer_state_key_t> keys;

	void SetUp() override
	{
		const auto size = balancer_state_ht::calculate_sizeof(total_size);
		ASSERT_GT(size, sizeof(balancer_state_ht));
		// Value-initialize the whole allocation, including both runtime buckets.
		storage = std::make_unique<char[]>(size);
		ht = new (storage.get()) balancer_state_ht;
		updater.update_pointer(ht, 0, total_size);

		balancer_state_key_t key;
		memset(&key, 0, sizeof(key));
		key.balancer_id = 1;
		key.protocol = IPPROTO_TCP;
		key.addr_type = 4;
		key.ip_source.mapped_ipv4_address.address = rte_cpu_to_be_32(0xC0000201u);
		key.ip_destination.mapped_ipv4_address.address = rte_cpu_to_be_32(0xC6336401u);
		key.port_destination = rte_cpu_to_be_16(443);

		// With two buckets, these hashes select bucket 0 and home slot 31.
		for (uint32_t port = 0; port <= 0xFFFFu && keys.size() < 33; ++port)
		{
			key.port_source = rte_cpu_to_be_16(static_cast<uint16_t>(port));
			if ((dataplane::calculate_hash_xxh32(key) & 0x3Fu) == 0x3Eu)
			{
				keys.push_back(key);
			}
		}
		ASSERT_EQ(33u, keys.size());
	}

	void TearDown() override
	{
		if (ht)
		{
			ht->~balancer_state_ht();
		}
	}

	static balancer_state_value_t make_value(uint32_t id)
	{
		return {0x31337u + id, 100u + id, 200u + id, 300u + id, 400u + id};
	}

	void fill_bucket()
	{
		for (uint32_t i = 0; i < 32; ++i)
		{
			ASSERT_TRUE(ht->insert_or_update(keys[i], make_value(i))) << i;
		}
	}

	std::optional<balancer_state_value_t> lookup(const balancer_state_key_t& key)
	{
		balancer_state_value_t* value;
		dataplane::spinlock_nonrecursive_t* locker;
		const auto hash = ht->lookup(key, value, locker);
		std::optional<balancer_state_value_t> result;
		if (value)
		{
			result = *value;
		}
		locker->unlock();
		EXPECT_EQ(dataplane::calculate_hash_xxh32(key), hash);
		return result;
	}

	void expect_value(const balancer_state_key_t& key, const balancer_state_value_t& expected)
	{
		const auto value = lookup(key);
		ASSERT_TRUE(value.has_value());
		EXPECT_EQ(expected.real_unordered_id, value->real_unordered_id);
		EXPECT_EQ(expected.timestamp_create, value->timestamp_create);
		EXPECT_EQ(expected.timestamp_last_packet, value->timestamp_last_packet);
		EXPECT_EQ(expected.timestamp_gc, value->timestamp_gc);
		EXPECT_EQ(expected.state_timeout, value->state_timeout);
	}
};

TEST_F(BalancerStateHashtableTest, BucketCapacityAndUpdates)
{
	ASSERT_NO_FATAL_FAILURE(fill_bucket());
	EXPECT_FALSE(ht->insert_or_update(keys[32], make_value(32)));
	EXPECT_FALSE(lookup(keys[32]).has_value());
	for (uint32_t i = 0; i < 32; ++i)
	{
		expect_value(keys[i], make_value(i));
	}

	uint32_t offset = 0;
	uint32_t slot = 0;
	for (auto iter : updater.range(offset, total_size))
	{
		const bool valid = iter.is_valid();
		EXPECT_EQ(slot < 32, valid);
		if (valid)
		{
			// Probing wraps from home slot 31 to slots 0 through 30.
			const auto& expected = keys[(slot + 1) % 32];
			EXPECT_EQ(0, memcmp(&expected, iter.key(), sizeof(expected)));
		}
		++slot;
	}
	EXPECT_EQ(total_size, slot);
	EXPECT_EQ(0u, offset);

	EXPECT_TRUE(ht->insert_or_update(keys[0], make_value(100)));
	expect_value(keys[0], make_value(100));
	EXPECT_TRUE(ht->insert_or_update(keys[31], make_value(131)));
	expect_value(keys[31], make_value(131));
}

TEST_F(BalancerStateHashtableTest, RemovalAndReinsertion)
{
	ASSERT_NO_FATAL_FAILURE(fill_bucket());
	ht->remove(keys[0]); // Home slot 31.
	ht->remove(keys[16]); // A displaced key in slot 15.
	EXPECT_FALSE(lookup(keys[0]).has_value());
	EXPECT_FALSE(lookup(keys[16]).has_value());
	for (uint32_t i = 1; i < 32; ++i)
	{
		if (i != 16)
		{
			expect_value(keys[i], make_value(i));
		}
	}

	EXPECT_TRUE(ht->insert_or_update(keys[0], make_value(100)));
	EXPECT_TRUE(ht->insert_or_update(keys[16], make_value(116)));
	expect_value(keys[0], make_value(100));
	expect_value(keys[16], make_value(116));
	EXPECT_FALSE(ht->insert_or_update(keys[32], make_value(32)));
}

TEST_F(BalancerStateHashtableTest, GcTraversalAndStatistics)
{
	ASSERT_NO_FATAL_FAILURE(fill_bucket());
	EXPECT_EQ(0u, updater.get_stats().keys_count);

	const auto scan = [&](uint32_t expected_keys) {
		const auto published = updater.get_stats();
		uint32_t offset = 0;
		uint32_t visited = 0;
		uint32_t valid_keys = 0;
		for (uint32_t from = 0; from < total_size; from += 8)
		{
			for (auto iter : updater.gc(offset, 8))
			{
				++visited;
				valid_keys += iter.is_valid();
			}
			EXPECT_EQ((from + 8) % total_size, offset);
			if (from + 8 < total_size)
			{
				const auto current = updater.get_stats();
				EXPECT_EQ(published.keys_count, current.keys_count);
				EXPECT_EQ(published.longest_chain, current.longest_chain);
				EXPECT_EQ(published.keys_in_chunks, current.keys_in_chunks);
			}
		}
		EXPECT_EQ(total_size, visited);
		EXPECT_EQ(expected_keys, valid_keys);

		const auto stats = updater.get_stats();
		EXPECT_EQ(expected_keys, stats.keys_count);
		EXPECT_EQ(expected_keys, stats.longest_chain);
		std::array<uint32_t, 33> histogram{};
		histogram[0] = 1;
		histogram[expected_keys] = 1;
		EXPECT_EQ(histogram, stats.keys_in_chunks);
	};

	scan(32);
	scan(32); // A new scan must not accumulate the previous generation.

	balancer_state_ht::iterator_t home(ht, 31);
	home.lock();
	const bool was_valid = home.is_valid();
	const auto mask_before = home.chunk().valid_mask;
	home.unset_valid();
	const auto mask_after = home.chunk().valid_mask;
	home.unlock();
	EXPECT_TRUE(was_valid);
	EXPECT_EQ(0xFFFFFFFFu, mask_before);
	EXPECT_EQ(0x7FFFFFFFu, mask_after);
	EXPECT_FALSE(lookup(keys[0]).has_value());
	scan(31);
}

}
