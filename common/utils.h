#pragma once

#include <atomic>
#include <bitset>
#include <iomanip>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace utils
{

template<typename Ptr>
Ptr ShiftBuffer(Ptr buffer, std::size_t offset)
{
	static_assert(std::is_pointer<Ptr>::value,
	              "ShiftBuffer<Ptr>: Ptr must be a pointer type");

	// pick a byte* of the correct constness
	using Pointee = typename std::remove_pointer<Ptr>::type;
	using BytePtr = typename std::conditional<
	        std::is_const<Pointee>::value,
	        const std::byte*,
	        std::byte*>::type;

	BytePtr b = reinterpret_cast<BytePtr>(buffer);
	b += offset;
	return reinterpret_cast<Ptr>(b);
}

template<typename ResultPtr, typename InputPtr>
ResultPtr ShiftBuffer(InputPtr buffer, std::size_t offset)
{
	static_assert(std::is_pointer<ResultPtr>::value,
	              "ShiftBuffer<ResultPtr,InputPtr>: ResultPtr must be a pointer");
	static_assert(std::is_pointer<InputPtr>::value,
	              "ShiftBuffer<ResultPtr,InputPtr>: InputPtr must be a pointer");

	// same BytePtr choosing trick
	using InPointee = typename std::remove_pointer<InputPtr>::type;
	using BytePtr = typename std::conditional<
	        std::is_const<InPointee>::value,
	        const std::byte*,
	        std::byte*>::type;

	BytePtr b = reinterpret_cast<BytePtr>(buffer);
	b += offset;
	return reinterpret_cast<ResultPtr>(b);
}

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

class Job
{
	std::atomic<bool> run_;
	std::thread thread_;

public:
	Job() :
	        run_{false} {}
	Job(Job&& other) = delete;
	Job& operator=(Job&& other) = delete;
	Job(const Job& other) = delete;
	Job& operator=(const Job& other) = delete;
	~Job()
	{
		Stop();
	}

	template<typename Task, typename... Args>
	void Run(Task&& task, Args&&... args)
	{
		Stop();

		run_.store(true, std::memory_order_relaxed);

		auto work_loop = [this,
		                  task = std::forward<Task>(task),
		                  args_tuple = std::make_tuple(std::forward<Args>(args)...)]() mutable {
			while (run_.load(std::memory_order_acquire))
			{
				if (!std::apply(task, args_tuple))
				{
					break;
				}
			}
		};

		thread_ = std::thread(std::move(work_loop));
	}

	bool Running() const
	{
		return thread_.joinable();
	}

	void Stop()
	{
		run_.store(false, std::memory_order_release);
		if (thread_.joinable())
		{
			thread_.join();
		}
	}
};

}
// namespace utils
