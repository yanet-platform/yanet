#pragma once
#include <mutex>

#include <rte_mbuf.h>

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

template<typename T>
class Sequential
{
	std::mutex mutex_;
	T data_;

public:
	template<typename F>
	auto apply(F func)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		return func(data_);
	}
};

} // namespace utils
