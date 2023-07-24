#pragma once

#include <cstdint>

namespace common
{

typedef unsigned int uint128_t __attribute__((mode(TI)));

inline namespace literals
{
	/// User-defined literal that allows to initialize 128-bit numbers.
	///
	/// For example: `auto mask = 0x1111222233330000aaaabbbb00000000_uint128_t;`.
	constexpr uint128_t operator""_uint128_t(const char* literal)
	{
		uint128_t out = 0;
		for (int i = 2; literal[i] != '\0'; ++i)
		{
			out *= 16ULL;
			if ('0' <= literal[i] && literal[i] <= '9')
			{
				out += literal[i] - '0';
			}
			else if ('A' <= literal[i] && literal[i] <= 'F')
			{
				out += literal[i] - 'A' + 10;
			}
			else if ('a' <= literal[i] && literal[i] <= 'f')
			{
				out += literal[i] - 'a' + 10;
			}
		}

		return out;
	}

} // namespace literals

/// Returns the number of 1-bits in n.
inline uint8_t popcount_u128(uint128_t n)
{
	const uint64_t n_hi = n >> 64;
	const uint64_t n_lo = n;
	const uint8_t count_hi = __builtin_popcountll(n_hi);
	const uint8_t count_lo = __builtin_popcountll(n_lo);
	const uint8_t count = count_hi + count_lo;

	return count;
}

} // namespace common
