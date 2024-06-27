#include "slow_worker.h"

#include "common/type.h"
#include "controlplane.h"
#include "worker.h"

namespace dataplane
{

SlowWorker::SlowWorker(cControlPlane* cplane) :
        cplane_{cplane} {}
const dataplane::base::generation& SlowWorker::current_base()
{
	return cplane_->slowWorker->current_base();
}
void SlowWorker::SendToSlowWorker(rte_mbuf* pkt, const common::globalBase::tFlow& flow)
{
	cplane_->sendPacketToSlowWorker(pkt, flow);
}
void SlowWorker::PreparePacket(rte_mbuf* pkt)
{
	cplane_->slowWorker->preparePacket(pkt);
}

} // dataplane