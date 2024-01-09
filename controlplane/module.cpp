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
	for (auto& func : funcThreads)
	{
		threads.emplace_back([func = std::move(func)]() {
			try
			{
				func();
			}
			catch (const std::exception& exception)
			{
				YANET_LOG_ERROR("Terminate due to exception %s\n", exception.what());
				throw;
			}
			catch (const std::string& string)
			{
				YANET_LOG_ERROR("Terminate due to string exception %s\n", string.data());
				throw;
			}
			catch (...)
			{
				YANET_LOG_ERROR("Terminate due to unknown error\n");
				throw;
			}
		});
	}
	funcThreads.clear();
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
