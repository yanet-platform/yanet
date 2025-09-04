#pragma once

#include <atomic>
#include <bitset>
#include <thread>

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
