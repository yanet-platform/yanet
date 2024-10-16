#pragma once

#include <iomanip>
#include <vector>
#include <type_traits>
#include <iomanip>
#include <string>
#include <type_traits>

namespace utils
{

// Utility to calculate percentage
// TODO C++20: use std::type_identity_t to establish non-deduced context
// Will allow to do `to_percent(4.2, 1)`
template<typename T>
inline std::string to_percent(T current, T maximum = 1)
{
	double percent = 0.0;
	if (maximum != 0)
	{
		percent = static_cast<double>(current) / static_cast<double>(maximum) * 100.0;
	}

	std::ostringstream stream;
	stream << std::fixed << std::setprecision(2) << percent;
	return stream.str();
}

// Split a string_view into a vector of strings based on a delimiter
inline std::vector<std::string> split(const std::string_view str, char delimiter)
{
	std::vector<std::string> result;
	size_t start = 0;
	size_t end = 0;

	while ((end = str.find(delimiter, start)) != std::string_view::npos)
	{
		result.emplace_back(str.substr(start, end - start));
		start = end + 1;
	}
	result.emplace_back(str.substr(start));
	return result;
}

// Split for std::string but disabled for const char* to avoid ambiguity
template<typename T, typename = std::enable_if_t<!std::is_same_v<T, const char*>>>
inline std::vector<std::string> split(const std::string& str, char delimiter)
{
	return split(std::string_view(str), delimiter);
}

inline std::string hexdump(std::string_view data)
{
	std::ostringstream oss;
	oss << std::hex << std::setfill('0'); // Set hexadecimal formatting and fill character

	const size_t size = data.size();

	for (size_t offset = 0; offset < size; offset += 16)
	{
		// Output the offset
		oss << std::setw(8) << offset << "  ";

		// Prepare ASCII representation
		std::string ascii_representation;
		ascii_representation.reserve(16);

		const size_t line_size = std::min(size - offset, size_t(16));

		for (size_t i = 0; i < 16; ++i)
		{
			// Add extra space after 8 bytes
			if (i == 8)
			{
				oss << "  ";
			}
			else if (i != 0)
			{
				oss << ' ';
			}

			if (i < line_size)
			{
				const auto byte = static_cast<unsigned char>(data[offset + i]);
				oss << std::setw(2) << static_cast<int>(byte);

				ascii_representation += std::isprint(byte) ? byte : '.';
			}
			else
			{
				// Fill in spaces for alignment if line is shorter than 16 bytes
				oss << "  ";
				ascii_representation += ' ';
			}
		}

		// Append ASCII representation
		oss << "  |" << ascii_representation << "|\n";
	}

	return oss.str();
}
}
// namespace utils
