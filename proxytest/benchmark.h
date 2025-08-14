#pragma once

#include <chrono>
#include <vector>
#include <map>

#include "dataplane/globalbase.h"
#include "dataplane/proxy.h"

struct Config
{
    bool help = false;
    unsigned int syn_threads;
    unsigned int threads;
    std::vector<uint32_t> syn_cores;
    std::vector<uint32_t> cores;
    std::chrono::duration<double> duration;
    uint64_t synflood_packets;
};

struct Stats
{
    uint64_t client_syn_dropped;
    uint64_t client_ack_dropped;
    uint64_t server_synack_dropped;
    uint64_t server_ack_dropped;
    uint64_t counters[64]{};

    std::vector<uint64_t> iterations;
};

struct WorkerArgs
{
    dataplane::proxy::TcpConnectionStore* tcp_connection_store;
    dataplane::base::generation* base;
    dataplane::proxy::proxy_service_t* service;
    Stats* stats;
    uint32_t* current_time;
    uint64_t* current_time_ms;
    rte_mbuf* mbuf;
};

void Benchmark(const Config& config);
