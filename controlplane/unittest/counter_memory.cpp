#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>

#include "controlplane/counter.h"

namespace
{

// The copy made after `copies` successful ones throws.
struct throwing_key_t
{
	int value;
	int* copies;

	throwing_key_t(int value, int* copies) :
	        value(value),
	        copies(copies)
	{
	}

	throwing_key_t(const throwing_key_t& other) :
	        value(other.value),
	        copies(other.copies)
	{
		if ((*copies)-- == 0)
		{
			throw std::runtime_error("copy failed");
		}
	}

	bool operator<(const throwing_key_t& other) const { return value < other.value; }
};

TEST(CounterMemory, FailedInsertReleasesCounters)
{
	auto manager = std::make_unique<counter_manager_t>();
	counter_t<throwing_key_t, 2> counters;
	counters.init(manager.get());
	const auto initial = manager->stats();

	// The first copy enters the counter map, the second one fails.
	int copies = 1;
	try
	{
		counters.insert({1, &copies});
	}
	catch (const std::runtime_error&)
	{
	}

	EXPECT_EQ(manager->stats(), initial);
}

}
