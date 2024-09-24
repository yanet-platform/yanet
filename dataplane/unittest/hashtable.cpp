#include <gtest/gtest.h>

#include "../hashtable.h"
#include "../type.h"

namespace
{

TEST(HashtableTest, Basic)
{
	dataplane::hashtable_chain_t<int, int, 128, 128, 4, 4> t;

	int* v = nullptr;
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
		int* v = nullptr;
		dataplane::spinlock_t* locker = nullptr;

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
	EXPECT_NE(t.stats().extendedChunksCount, 0);

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

	EXPECT_EQ(t.stats().extendedChunksCount, 0);
	EXPECT_EQ(t.stats().pairs, 0);

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

	EXPECT_EQ(t.stats().extendedChunksCount, 0);
	EXPECT_EQ(t.stats().pairs, 0);

	for (int k = 0; k < 100500; ++k)
	{
		t.insert(k, k);
	}

	EXPECT_EQ(t.stats().extendedChunksCount, 128);
	EXPECT_EQ(t.stats().pairs, 128 * 2 + 128 * 4);

	t.clear();

	EXPECT_EQ(t.stats().extendedChunksCount, 0);
	EXPECT_EQ(t.stats().pairs, 0);
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
		for (unsigned int value : values)
		{
			EXPECT_EQ(0x80000000, value & (1u << 31));
		}
	}

	for (auto key : keys)
	{
		EXPECT_EQ(eResult::success, ht.insert(updater, key, value1));
	}

	{
		const auto mask = ht.lookup(hashes, keys, values, YANET_CONFIG_BURST_SIZE);
		EXPECT_EQ(0xFFFFFFFF, mask);
		for (unsigned int value : values)
		{
			EXPECT_EQ(value1, value);
		}
	}

	for (auto key : keys)
	{
		EXPECT_EQ(eResult::success, ht.insert(updater, key, value2));
	}

	{
		const auto mask = ht.lookup(hashes, keys, values, YANET_CONFIG_BURST_SIZE);
		EXPECT_EQ(0xFFFFFFFF, mask);
		for (unsigned int value : values)
		{
			EXPECT_EQ(value2, value);
		}
	}

	ht.clear();

	{
		const auto mask = ht.lookup(hashes, keys, values, YANET_CONFIG_BURST_SIZE);
		EXPECT_EQ(0, mask);
		for (unsigned int value : values)
		{
			EXPECT_EQ(0x80000000, value & (1u << 31));
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

	uint32_t* value = nullptr;
	dataplane::spinlock_nonrecursive_t* locker = nullptr;

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

	uint32_t* value = nullptr;
	dataplane::spinlock_nonrecursive_t* locker = nullptr;

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

}
