#include <gtest/gtest.h>
#include <random>
#include <vector>

#include "../bits_ops.h"

#define RANDOM_INIT 32
#define NUMBER_RANDOMS 1000

std::vector<uint32_t> GetTestNumbers32()
{
	std::mt19937 generator(RANDOM_INIT);
	std::uniform_int_distribution<> distribution(0, 0xffff);
	std::vector<uint32_t> result;
	result.push_back(0);
	result.push_back(static_cast<uint32_t>(-1));
	for (int i = 0; i < NUMBER_RANDOMS; i++)
	{
		uint32_t hi = distribution(generator);
		uint32_t low = distribution(generator);
		result.push_back((hi << 16) | low);
	}
	return result;
}

std::vector<uint64_t> GetTestNumbers64()
{
	std::mt19937 generator(RANDOM_INIT);
	std::uniform_int_distribution<> distribution(0, 0xffff);
	std::vector<uint64_t> result;
	result.push_back(0);
	result.push_back(static_cast<uint32_t>(-1));
	for (int i = 0; i < NUMBER_RANDOMS; i++)
	{
		uint64_t part1 = distribution(generator);
		uint64_t part2 = distribution(generator);
		uint64_t part3 = distribution(generator);
		uint64_t part4 = distribution(generator);
		result.push_back((part1 << 48) | (part2 << 48) | (part3 << 48) | part4);
	}
	return result;
}

template<typename Func1, typename Func2>
void Test32Bits(Func1 func1, Func2 func2)
{
	std::vector<uint32_t> numbers = GetTestNumbers32();
	for (uint32_t value : numbers)
	{
		for (uint8_t bit = 0; bit < 32; bit++)
		{
			ASSERT_EQ(func1(value, bit), func2(value, bit)) << "value = " << value << ", bit = " << (uint16_t)bit << "\n";
		}
	}
}

template<typename Func1, typename Func2>
void Test64Bits(Func1 func1, Func2 func2)
{
	std::vector<uint64_t> numbers = GetTestNumbers64();
	for (uint64_t value : numbers)
	{
		for (uint8_t bit = 0; bit < 64; bit++)
		{
			ASSERT_EQ(func1(value, bit), func2(value, bit)) << "value = " << value << ", bit = " << (uint16_t)bit << "\n";
		}
	}
}

template<typename Func1, typename Func2>
void Test32(Func1 func1, Func2 func2)
{
	std::vector<uint32_t> numbers = GetTestNumbers32();
	for (uint32_t value : numbers)
	{
		ASSERT_EQ(func1(value), func2(value)) << "value = " << value << "\n";
	}
}

template<typename Func1, typename Func2>
void Test64(Func1 func1, Func2 func2)
{
	std::vector<uint64_t> numbers = GetTestNumbers64();
	for (uint64_t value : numbers)
	{
		ASSERT_EQ(func1(value), func2(value)) << "value = " << value << "\n";
	}
}

namespace
{

template<typename T>
uint8_t TestGetBit(T value, uint8_t index)
{
	for (uint8_t i = 0; i < index; i++)
	{
		value /= 2;
	}
	return value % 2;
}

TEST(Bits, get_bit)
{
	// 0x55 - binary: 01010101
	// 0xaa - binary: 10101010

	for (uint8_t bit = 0; bit < 32; bit++)
	{
		ASSERT_EQ(common::bits::get_bit_32(0x55555555, bit), 1 - (bit & 0x1));
		ASSERT_EQ(common::bits::get_bit_32(0xaaaaaaaa, bit), (bit & 0x1));
		ASSERT_EQ(common::bits::get_bit_32(0x00000001, bit), (bit == 0 ? 1 : 0));
		ASSERT_EQ(common::bits::get_bit_32(0x80000000, bit), (bit == 31 ? 1 : 0));
	}

	for (uint8_t bit = 0; bit < 64; bit++)
	{
		ASSERT_EQ(common::bits::get_bit_64(0x5555555555555555, bit), 1 - (bit & 0x1));
		ASSERT_EQ(common::bits::get_bit_64(0xaaaaaaaaaaaaaaaa, bit), (bit & 0x1));
		ASSERT_EQ(common::bits::get_bit_64(0x0000000000000001, bit), (bit == 0 ? 1 : 0));
		ASSERT_EQ(common::bits::get_bit_64(0x8000000000000000, bit), (bit == 63 ? 1 : 0));
	}

	{
		std::vector<uint32_t> numbers = GetTestNumbers32();
		for (uint32_t value : numbers)
		{
			for (uint8_t bit = 0; bit < 32; bit++)
			{
				ASSERT_EQ(common::bits::get_bit_32(value, bit), TestGetBit(value, bit)) << "value = " << value << ", bit = " << (uint16_t)bit << "\n";
			}
		}
	}

	Test32Bits(common::bits::get_bit_32, TestGetBit<uint32_t>);
	Test64Bits(common::bits::get_bit_64, TestGetBit<uint64_t>);
}

TEST(Bits, enable_bit)
{
	for (int bit1 = 0; bit1 < 32; bit1++)
	{
		uint32_t value = 0;
		common::bits::enable_bit_32(value, bit1);
		for (int bit2 = 0; bit2 < 32; bit2++)
		{
			ASSERT_EQ(common::bits::get_bit_32(value, bit2), (bit1 == bit2 ? 1 : 0));
		}
	}

	for (int bit1 = 0; bit1 < 64; bit1++)
	{
		uint64_t value = 0;
		common::bits::enable_bit_64(value, bit1);
		for (int bit2 = 0; bit2 < 64; bit2++)
		{
			ASSERT_EQ(common::bits::get_bit_64(value, bit2), (bit1 == bit2 ? 1 : 0));
		}
	}

	{
		std::vector<uint32_t> numbers = GetTestNumbers32();
		for (uint32_t value : numbers)
		{
			for (uint8_t bit = 0; bit < 32; bit++)
			{
				uint32_t changed = value;
				common::bits::enable_bit_32(changed, bit);
				ASSERT_TRUE((common::bits::get_bit_32(changed, bit) == 1) && ((value == changed) || ((value ^ changed) == (1u << bit))))
				        << "value = " << value << ", bit = " << (uint16_t)bit << "\n";
			}
		}
	}

	{
		std::vector<uint64_t> numbers = GetTestNumbers64();
		for (uint64_t value : numbers)
		{
			for (uint8_t bit = 0; bit < 64; bit++)
			{
				uint64_t changed = value;
				common::bits::enable_bit_64(changed, bit);
				ASSERT_TRUE((common::bits::get_bit_64(changed, bit) == 1) && ((value == changed) || ((value ^ changed) == (1ull << bit))))
				        << "value = " << value << ", bit = " << (uint16_t)bit << "\n";
			}
		}
	}
}

TEST(Bits, disable_bit)
{
	for (int bit1 = 0; bit1 < 32; bit1++)
	{
		uint32_t value0 = 0;
		uint32_t value1 = 0xffffffff;
		common::bits::disable_bit_32(value0, bit1);
		common::bits::disable_bit_32(value1, bit1);
		for (int bit2 = 0; bit2 < 32; bit2++)
		{
			ASSERT_EQ(common::bits::get_bit_32(value0, bit2), 0);
			ASSERT_EQ(common::bits::get_bit_32(value1, bit2), (bit1 == bit2 ? 0 : 1));
		}
	}

	{
		uint32_t value1 = 0xffffffff;
		for (int bit1 = 0; bit1 < 32; bit1++)
		{
			common::bits::disable_bit_32(value1, bit1);
			for (int bit2 = 0; bit2 < 32; bit2++)
			{
				ASSERT_EQ(common::bits::get_bit_32(value1, bit2), (bit1 >= bit2 ? 0 : 1));
			}
		}
	}

	for (int bit1 = 0; bit1 < 64; bit1++)
	{
		uint64_t value0 = 0;
		uint64_t value1 = 0xffffffffffffffff;
		common::bits::disable_bit_64(value0, bit1);
		common::bits::disable_bit_64(value1, bit1);
		for (int bit2 = 0; bit2 < 64; bit2++)
		{
			ASSERT_EQ(common::bits::get_bit_64(value0, bit2), 0);
			ASSERT_EQ(common::bits::get_bit_64(value1, bit2), (bit1 == bit2 ? 0 : 1));
		}
	}

	{
		uint64_t value1 = 0xffffffffffffffff;
		for (int bit1 = 0; bit1 < 64; bit1++)
		{
			common::bits::disable_bit_64(value1, bit1);
			for (int bit2 = 0; bit2 < 64; bit2++)
			{
				ASSERT_EQ(common::bits::get_bit_64(value1, bit2), (bit1 >= bit2 ? 0 : 1));
			}
		}
	}

	{
		std::vector<uint32_t> numbers = GetTestNumbers32();
		for (uint32_t value : numbers)
		{
			for (uint8_t bit = 0; bit < 32; bit++)
			{
				uint32_t changed = value;
				common::bits::disable_bit_32(changed, bit);
				ASSERT_TRUE((common::bits::get_bit_32(changed, bit) == 0) && ((value == changed) || ((value ^ changed) == (1u << bit))))
				        << "value = " << value << ", bit = " << (uint16_t)bit << "\n";
			}
		}
	}

	{
		std::vector<uint64_t> numbers = GetTestNumbers64();
		for (uint64_t value : numbers)
		{
			for (uint8_t bit = 0; bit < 64; bit++)
			{
				uint64_t changed = value;
				common::bits::disable_bit_64(changed, bit);
				ASSERT_TRUE((common::bits::get_bit_64(changed, bit) == 0) && ((value == changed) || ((value ^ changed) == (1ull << bit))))
				        << "value = " << value << ", bit = " << (uint16_t)bit << "\n";
			}
		}
	}
}

template<typename T>
uint8_t TestCountOnes(T value)
{
	uint8_t result = 0;
	while (value != 0)
	{
		result += (value % 2);
		value /= 2;
	}
	return result;
}

TEST(Bits, count_ones)
{
	ASSERT_EQ(common::bits::count_ones_32(0u), 0);
	ASSERT_EQ(common::bits::count_ones_64(0ull), 0);

	for (int bit1 = 0; bit1 < 32; bit1++)
	{
		uint32_t value = 0;
		for (int bit2 = bit1; bit2 < 32; bit2++)
		{
			common::bits::enable_bit_32(value, bit2);
			ASSERT_EQ(common::bits::count_ones_32(value), bit2 - bit1 + 1);
		}
	}

	for (int bit1 = 0; bit1 < 64; bit1++)
	{
		uint64_t value = 0;
		for (int bit2 = bit1; bit2 < 64; bit2++)
		{
			common::bits::enable_bit_64(value, bit2);
			ASSERT_EQ(common::bits::count_ones_64(value), bit2 - bit1 + 1);
		}
	}

	Test32(common::bits::count_ones_32, TestCountOnes<uint32_t>);
	Test64(common::bits::count_ones_64, TestCountOnes<uint64_t>);
}

TEST(Bits, build_mask)
{
	for (uint8_t length = 0; length <= 32; length++)
	{
		uint32_t value = 0;
		for (uint8_t bit = 0; bit < length; bit++)
		{
			common::bits::enable_bit_32(value, 31 - bit);
		}
		ASSERT_EQ(common::bits::build_mask_32(length), value);
	}

	for (uint8_t length = 0; length <= 64; length++)
	{
		uint64_t value = 0;
		for (uint8_t bit = 0; bit < length; bit++)
		{
			common::bits::enable_bit_64(value, 63 - bit);
		}
		ASSERT_EQ(common::bits::build_mask_64(length), value);
	}
}

uint8_t TestFirstEnabledBit32(uint64_t value)
{
	for (uint8_t index = 0; index < 32; index++)
	{
		if (common::bits::get_bit_32(value, 31 - index) == 1)
		{
			return index;
		}
	}
	return 32;
}

uint8_t TestFirstEnabledBit64(uint64_t value)
{
	for (uint8_t index = 0; index < 64; index++)
	{
		if (common::bits::get_bit_64(value, 63 - index) == 1)
		{
			return index;
		}
	}
	return 64;
}

TEST(Bits, get_first_enabled_bit)
{
	for (uint8_t length = 0; length <= 32; length++)
	{
		uint32_t mask = common::bits::build_mask_32(length);
		ASSERT_EQ(common::bits::get_first_enabled_bit_32(~mask), length);
	}

	for (uint8_t length = 0; length <= 64; length++)
	{
		uint64_t mask = common::bits::build_mask_64(length);
		ASSERT_EQ(common::bits::get_first_enabled_bit_64(~mask), length);
	}

	Test32(common::bits::get_first_enabled_bit_32, TestFirstEnabledBit32);
	Test64(common::bits::get_first_enabled_bit_64, TestFirstEnabledBit64);
}

template<typename T>
uint8_t TestGetLastEnabledBit(T value)
{
	for (uint8_t index = 0; index < 64; index++)
	{
		if (value % 2 == 1)
		{
			return index;
		}
		value /= 2;
	}
	return sizeof(T) * 8;
}

TEST(Bits, get_last_enabled_bit)
{
	for (uint8_t length = 0; length <= 32; length++)
	{
		uint32_t mask = common::bits::build_mask_32(length);
		ASSERT_EQ(common::bits::get_last_enabled_bit_32(mask), 32 - length);
	}

	for (uint8_t length = 0; length <= 64; length++)
	{
		uint64_t mask = common::bits::build_mask_64(length);
		ASSERT_EQ(common::bits::get_last_enabled_bit_64(mask), 64 - length);
	}

	Test32(common::bits::get_last_enabled_bit_32, TestGetLastEnabledBit<uint32_t>);
	Test64(common::bits::get_last_enabled_bit_64, TestGetLastEnabledBit<uint64_t>);
}

} // namespace
