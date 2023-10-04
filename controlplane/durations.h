#pragma once

#include <mutex>

#include "base.h"
#include "module.h"
#include "type.h"

class durations_t : public module_t
{
public:
	eResult init() override;

	void add(const std::string& name, double duration);
	template<typename T>
	std::chrono::time_point<T> add(const std::string& name, const std::chrono::time_point<T>& start)
	{
		auto now = T::now();
		add(name, std::chrono::duration<double>(now - start).count());

		return now;
	}

	common::icp::controlplane_durations::response getDurations() const;

protected:
	mutable std::mutex mutex;
	common::icp::controlplane_durations::response durations;
};
