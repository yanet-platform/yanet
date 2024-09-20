#pragma once

#include <cstddef>
#include <cstdint>

namespace common::bits
{
// Basic bit operations
// Each operation contains a 32 bit and a 64 bit version

// Get bit value for uint32_t, index: 0 - lowest bit, 31 - highest bit
inline uint8_t get_bit_32(uint32_t value, uint8_t index)
{
	return (value >> index) & 1;
}

// Get bit value for uint64_t, index: 0 - lowest bit, 63 - highest bit
inline uint8_t get_bit_64(uint64_t value, uint8_t index)
{
	return (value >> index) & 1;
}

// Enable bit in uint32_t, index: 0 - lowest bit, 31 - highest bit
inline void enable_bit_32(uint32_t& value, uint8_t index)
{
	value |= (1u << index);
}

// Enable bit in uint64_t, index: 0 - lowest bit, 63 - highest bit
inline void enable_bit_64(uint64_t& value, uint8_t index)
{
	value |= (1ull << index);
}

// Disable bit in uint32_t, index: 0 - lowest bit, 31 - highest bit
inline void disable_bit_32(uint32_t& value, uint8_t index)
{
	value &= ~(1u << index);
}

// Disable bit in uint64_t, index: 0 - lowest bit, 63 - highest bit
inline void disable_bit_64(uint64_t& value, uint8_t index)
{
	value &= ~(1ull << index);
}

// The number of ones in uint32_t value
inline uint8_t count_ones_32(uint32_t value)
{
	return __builtin_popcount(value);
}

// The number of ones in uint64_t value
inline uint8_t count_ones_64(uint64_t value)
{
	return __builtin_popcountll(value);
}

// Build a uint32_t with ones at the beginning, followed by zeros
// The return value looks like this: 1...10..0
inline uint32_t build_mask_32(uint8_t ones)
{
	return (ones == 0 ? 0 : static_cast<uint32_t>(-1) << (32 - ones));
}

// Build a uint64_t with ones at the beginning, followed by zeros
// The return value looks like this: 1...10..0
inline uint64_t build_mask_64(uint8_t ones)
{
	return (ones == 0 ? 0 : static_cast<uint64_t>(-1) << (64 - ones));
}

// Get the index of the highest enabled bit in uint32_t (for a zero value, the result is 32)
// 0 - highest bit, 31 - lowest bit
inline uint8_t get_first_enabled_bit_32(uint32_t value)
{
	return (value == 0 ? 32 : __builtin_clz(value));
}

// Get the index of the highest enabled bit in uint64_t (for a zero value, the result is 64)
// 0 - highest bit, 63 - lowest bit
inline uint8_t get_first_enabled_bit_64(uint64_t value)
{
	return (value == 0 ? 64 : __builtin_clzll(value));
}

// Get the index of the lowest enabled bit in uint32_t (for a zero value, the result is 32)
// 0 - lowest bit, 31 - highest bit
inline uint8_t get_last_enabled_bit_32(uint32_t value)
{
	return (value == 0 ? 32 : __builtin_ctz(value));
}

// Get the index of the lowest enabled bit in uint64_t (for a zero value, the result is 64)
// 0 - lowest bit, 63 - highest bit
inline uint8_t get_last_enabled_bit_64(uint64_t value)
{
	return (value == 0 ? 64 : __builtin_ctzll(value));
}
} // namespace common::bits
