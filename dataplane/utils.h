#pragma once
#include <rte_mbuf.h>

#include "common/config.h"
#include "common/define.h"
#include "common/type.h"
#include "dpdk.h"
#include "metadata.h"

namespace utils
{

inline void SetFlow(rte_mbuf* mbuf, const common::globalBase::tFlow& flow)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	metadata->flow = flow;
}

inline void SetFlowType(rte_mbuf* mbuf, const common::globalBase::eFlowType& type)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
	metadata->flow.type = type;
}

template<typename It>
class RoundRobinIterator
{
	It begin_;
	It end_;
	It curr_;

public:
	RoundRobinIterator(It range_start, It range_end) :
	        begin_{range_start}, end_{range_end}, curr_{range_start}
	{
	}
	It operator->() { return curr_; }
	RoundRobinIterator& operator++()
	{
		if (++curr_ == end_)
		{
			curr_ = begin_;
		}
		return *this;
	}
};

} // namespace utils