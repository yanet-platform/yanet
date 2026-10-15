#pragma once

#include <memory>
#include <new>

#include "dataplane/dataplane.h"
#include "dataplane/globalbase.h"
#include "dataplane/worker_gc.h"

namespace balancer_gc_test
{
namespace gb = dataplane::globalBase;

class Worker : public worker_gc_t
{
public:
	explicit Worker(cDataPlane* dataplane) :
	        worker_gc_t(dataplane)
	{
		stats = {};
		core_id = 0;
		socket_id = 0;
		current_time = 1000;
		gc_step = 8;
		sample_gc_step = 1;
		samples_current_base_id = 0;
		nat64stateful_lan_state_gc = {};
		nat64stateful_wan_state_gc = {};
		fw4_state_gc = {};
		fw6_state_gc = {};
	}

	~Worker()
	{
		// Tests may borrow a ring initialized without EAL, as isolation_worker does.
		ring_to_free_mbuf = nullptr;
		ring_to_slowworker = nullptr;
	}

	using worker_gc_t::balancer_next_real_entry;
	using worker_gc_t::handle;
	using worker_gc_t::handle_balancer_gc;
};

template<typename Table>
class RuntimeTable
{
	std::unique_ptr<char[]> storage;

public:
	explicit RuntimeTable(uint32_t slots) :
	        storage(std::make_unique<char[]>(Table::calculate_sizeof(slots))),
	        pointer(new(storage.get()) Table)
	{
	}

	~RuntimeTable()
	{
		pointer->~Table();
	}

	Table* pointer;
};

// The allocation sizes are runtime slot counts, not the production configuration defaults.
struct State
{
	static constexpr uint32_t slots = 64;
	std::unique_ptr<gb::atomic> atomic;
	RuntimeTable<gb::nat64stateful::wan_ht> wan{slots};
	RuntimeTable<gb::nat64stateful::lan_ht> lan{slots};
	RuntimeTable<gb::acl::ipv4_states_ht> fw4{slots};
	RuntimeTable<gb::acl::ipv6_states_ht> fw6{slots};
	RuntimeTable<gb::balancer::state_ht> balancer{slots};

	explicit State(cDataPlane& dataplane, tSocketId socket = 0) :
	        atomic(std::make_unique<gb::atomic>(&dataplane, socket))
	{
		atomic->currentTime = 1000;
		atomic->balancer_state_gc = {};
		atomic->nat64stateful_wan_state = wan.pointer;
		atomic->nat64stateful_lan_state = lan.pointer;
		atomic->fw4_state = fw4.pointer;
		atomic->fw6_state = fw6.pointer;
		atomic->balancer_state = balancer.pointer;
		atomic->updater.nat64stateful_wan_state.update_pointer(wan.pointer, socket, slots);
		atomic->updater.nat64stateful_lan_state.update_pointer(lan.pointer, socket, slots);
		atomic->updater.fw4_state.update_pointer(fw4.pointer, socket, slots);
		atomic->updater.fw6_state.update_pointer(fw6.pointer, socket, slots);
		atomic->updater.balancer_state.update_pointer(balancer.pointer, socket, slots);
	}
};

// No init()/EAL or generation::init(): only the fields used by GC are configured.
// Large production objects stay on the heap; this header has no GTest dependency.
struct Harness
{
	std::unique_ptr<cDataPlane> dataplane = std::make_unique<cDataPlane>();
	State state{*dataplane};
	std::unique_ptr<gb::generation> generation = std::make_unique<gb::generation>(dataplane.get(), 0);
	std::unique_ptr<Worker> worker = std::make_unique<Worker>(dataplane.get());

	Harness()
	{
		generation->decap_enabled = 0;
		generation->nat64stateful_enabled = 1;
		generation->nat64stateless_enabled = 0;
		generation->nat46clat_enabled = 0;
		generation->balancer_enabled = 1;
		generation->acl_egress_enabled = 0;
		generation->sampler_enabled = 0;
		generation->tun64_enabled = 0;
		generation->early_decap_enabled = 0;
		generation->serial = 0;
		generation->balancer_reals[0] = {};

		worker->base_permanently.globalBaseAtomic = state.atomic.get();
		worker->base_permanently.globalBaseAtomics[0] = state.atomic.get();
		worker->base_permanently.activeNumaNodesCount = 1;
		worker->bases[0].globalBase = generation.get();
		worker->bases[1] = worker->bases[0];
	}

	void tick()
	{
		// handle() needs an initialized free-mbuf ring.
		worker->local_base_id = worker->current_base_id;
		worker->handle();
		++worker->iteration;
	}
};
}
