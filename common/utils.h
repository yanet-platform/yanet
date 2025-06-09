#pragma once

#include <bitset>

namespace utils
{

// Converts a std::bitset to a hexadecimal string representation.
template<size_t N>
std::string bitset_to_hex_string(const std::bitset<N>& bs)
{
	static_assert(N % 4 == 0, "Bitset size must be a multiple of 4 for hex conversion.");

	std::stringstream ss;
	ss << "0x";

	// We iterate from the most significant nibble (group of 4 bits) to the least.
	for (int bit_index = N - 4; bit_index >= 0; bit_index -= 4)
	{
		unsigned int nibble = 0;
		// Convert 4 bits to an integer value (0-15)
		for (int j = 0; j < 4; ++j)
		{
			if (bs.test(bit_index + j))
			{
				nibble |= (1 << j);
			}
		}
		ss << std::hex << nibble;
	}
	return ss.str();
}

}
// namespace utils
