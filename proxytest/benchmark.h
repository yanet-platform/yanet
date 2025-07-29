#pragma once

#include <chrono>

struct Config {
    bool help = false;
    unsigned int syn_threads;
    unsigned int threads;
    std::chrono::duration<double> duration;
    uint64_t synflood_packets;
};

void Benchmark(const Config& config);