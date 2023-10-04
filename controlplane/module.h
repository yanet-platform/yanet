#pragma once

#include <functional>
#include <thread>
#include <vector>

#include "common/icp.h"
#include "common/idp.h"
#include "common/result.h"

#include "common.h"
#include "type.h"

//

class cControlPlane;

//

class cModule
{
public:
	cModule();
	virtual ~cModule();

	eResult moduleInit(cControlPlane* controlPlane);
	void moduleStart();
	void moduleStop();
	void moduleJoin();

	virtual void limit(common::icp::limit_summary::response& limits) const;
	virtual void controlplane_values(common::icp::controlplane_values::response& controlplane_values) const;
	virtual void reload_before();
	virtual void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase);
	virtual void reload_after();
	virtual void mac_addresses_changed();

protected:
	virtual eResult init();
	virtual void start();
	virtual void stop();
	virtual void join();

protected:
	cControlPlane* controlPlane;

	volatile bool flagStop;
	std::vector<std::function<void()>> funcThreads;
	std::vector<std::thread> threads;
};

using module_t = cModule;
