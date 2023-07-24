#include "module.h"

cModule::cModule() :
        controlPlane(nullptr),
        flagStop(false)
{
}

cModule::~cModule()
{
}

eResult cModule::moduleInit(cControlPlane* controlPlane)
{
	this->controlPlane = controlPlane;
	return init();
}

void cModule::moduleStart()
{
	for (const auto& func : funcThreads)
	{
		threads.emplace_back(func);
	}

	start();
}

void cModule::moduleStop()
{
	flagStop = true;

	stop();
}

void cModule::moduleJoin()
{
	for (auto& thread : threads)
	{
		if (thread.joinable())
		{
			thread.join();
		}
	}

	join();
}

void cModule::limit(common::icp::limit_summary::response& limits) const
{
	(void)limits;
}

void cModule::controlplane_values(common::icp::controlplane_values::response& controlplane_values) const
{
	(void)controlplane_values;
}

void cModule::reload_before()
{
}

void cModule::reload(const controlplane::base_t& base_prev,
                     const controlplane::base_t& base_next,
                     common::idp::updateGlobalBase::request& globalbase)
{
	(void)base_prev;
	(void)base_next;
	(void)globalbase;
}

void cModule::reload_after()
{
}

void cModule::mac_addresses_changed()
{
}

eResult cModule::init()
{
	return eResult::success;
}

void cModule::start()
{
}

void cModule::stop()
{
}

void cModule::join()
{
}
