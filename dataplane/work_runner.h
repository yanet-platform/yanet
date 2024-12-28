#pragma once
#include <chrono>
#include <thread>
#include <tuple>

namespace dpdk
{

namespace internal
{
template<typename F>
void CallIteration(F* f)
{
	f->Iteration();
}

template<typename F>
void CallIteration(F f)
{
	f.Iteration();
}

} // namespace internal

template<typename... Workloads>
class WorkRunner
{
	std::tuple<Workloads...> m_workers;
	template<int I = 0>
	void Iteration()
	{
		if constexpr (I != sizeof...(Workloads))
		{
			internal::CallIteration(std::get<I>(m_workers));
			Iteration<I + 1>();
		}
	}

public:
	void Run()
	{
		while (true)
		{
			Iteration();
		}
	}
	WorkRunner(Workloads... loads) :
	        m_workers{loads...}
	{
	}
};

template<int duration_value = 1, typename Duration = std::chrono::microseconds>
class Sleeper
{
public:
	void Iteration()
	{
		std::this_thread::sleep_for(Duration{duration_value});
	}
};

struct Yielder
{
	void Iteration()
	{
		std::this_thread::yield();
	}
};

} // namespace dpdk