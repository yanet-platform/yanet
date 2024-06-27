#pragma once
#include "base.h"

class cControlPlane;

namespace dataplane
{

/*
 * Stub of SlowWorker to divide refactoring dregress and cControlPlane
 */
class SlowWorker
{
	cControlPlane* cplane_;
public:
	explicit SlowWorker(cControlPlane* cplane);
	const dataplane::base::generation& current_base();
	void SendToSlowWorker(rte_mbuf* pkt, const common::globalBase::tFlow& flow);
	void PreparePacket(rte_mbuf* pkt);
};

} // namespace dataplane