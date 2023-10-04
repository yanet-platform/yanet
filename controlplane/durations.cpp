#include "durations.h"
#include "controlplane.h"

eResult durations_t::init()
{
	controlPlane->register_command(common::icp::requestType::controlplane_durations, [this]() {
		return getDurations();
	});

	return eResult::success;
}

void durations_t::add(const std::string& name, double duration)
{
	std::lock_guard<std::mutex> lock(mutex);

	durations[name] = duration;
}

common::icp::controlplane_durations::response durations_t::getDurations() const
{
	std::lock_guard<std::mutex> lock(mutex);

	return durations;
}
