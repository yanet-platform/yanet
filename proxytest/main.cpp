#include <iostream>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <bitset>
#include <sstream>
#include <rte_eal.h>
#include <inttypes.h>

#include "common/define.h"

#include "benchmark.h"

std::chrono::duration<double> ParseDuration(const std::string& arg) {
    switch (arg[arg.size() - 1])
    {
        case 'm':
            return std::chrono::duration<double>(std::chrono::minutes(std::stoi(arg)));
        case 's':
        default:
            return std::chrono::duration<double>(std::chrono::seconds(std::stoi(arg)));
    }
}

std::vector<uint32_t> ParseCores(const std::string& arg) {
    std::vector<uint32_t> cores;

    std::stringstream ss(arg);
    std::string item;
    while (std::getline(ss, item, ',')) {
        cores.push_back(std::stoi(item));
    }

    return cores;
}

typedef std::function<void(Config&)> NoArgHandle;
#define S1(str, f, v) {str, [](Config& c) { c.f = v; }}
const std::unordered_map<std::string, NoArgHandle> NoArgs = {
    S1("--help", help, true),
    S1("-h", help, true),
};

typedef std::function<void(Config&, const std::string&)> ArgHandle;
#define S2(str, f, v) {str, [](Config& c, const std::string& arg) { c.f = v; }}
const std::unordered_map<std::string, ArgHandle> OneArgs = {
    S2("--syn-threads", syn_threads, std::stoi(arg)),
    S2("-s", syn_threads, std::stoi(arg)),
    S2("--threads", threads, std::stoi(arg)),
    S2("-t", threads, std::stoi(arg)),
    S2("--syn-cores", syn_cores, ParseCores(arg)),
    S2("--cores", cores, ParseCores(arg)),
    S2("--duration", duration, ParseDuration(arg)),
    S2("-d", duration, ParseDuration(arg)),
    S2("--synflood-packets", synflood_packets, std::stoi(arg))
};

Config ParseArgs(int argc, char** argv) {
    Config config{};

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        
        if (auto j = NoArgs.find(arg); j != NoArgs.end()) {
            j->second(config);
        } else if (auto j = OneArgs.find(arg); j != OneArgs.end()) {
            if (++i < argc) j->second(config, argv[i]);
            else throw std::invalid_argument("Missing argument for " + arg);
        }
    }

    return config;
}

void Help(char ** argv)
{
    std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "-s, --syn-threads <n>" << std::endl;
    std::cout << "\tNumber of SYN flood threads(core agnostic)" << std::endl;
    std::cout << "-t, --threads <n>" << std::endl;
    std::cout << "\tNumber of normal traffic threads(core agnostic)" << std::endl;
    std::cout << "--syn-cores <1,2,3,4,...>" << std::endl;
    std::cout << "\tSpecify SYN flood cores" << std::endl;
    std::cout << "--cores <1,2,3,4,...>" << std::endl;
    std::cout << "\tSpecify normal traffic cores" << std::endl;
    std::cout << "-d, --duration <n>[s/m]" << std::endl;
    std::cout << "\tDuration of the test in seconds or minutes" << std::endl;
    std::cout << "--synflood-packets <n>" << std::endl;
    std::cout << "\tMax number of SYN flood packets to send for each syn thread/core" << std::endl;
    std::cout << "Note that --syn-cores/--cores and --syn-threads/--threads are mutually exclusive" << std::endl;
}

int main(int argc, char** argv){
    Config config = ParseArgs(argc, argv);
    bool cores = !config.syn_cores.empty() || !config.cores.empty();
    bool threads = config.syn_threads != 0 || config.threads != 0;
    if (config.help 
        || (config.duration.count() == 0 && config.synflood_packets == 0)
        || (!cores && !threads) || (cores && threads))
    {
        Help(argv);
        return 0;
    }
    if (cores)
    {
        config.syn_threads = config.syn_cores.size();
        config.threads = config.cores.size();
    }

    Benchmark(config);

    return 0;
}
