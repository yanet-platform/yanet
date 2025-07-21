#include <iostream>
#include <unordered_map>
#include <functional>
#include <chrono>

#include "benchmark.h"

struct Config {
    bool help = false;
    unsigned int syn_threads;
    unsigned int threads;
    std::chrono::duration<double> duration;
};

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
    S2("--duration", duration, ParseDuration(arg)),
    S2("-d", duration, ParseDuration(arg))
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

int main(int argc, char** argv){
    Config config = ParseArgs(argc, argv);
    if (config.help) {
        std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "-s, --syn-threads <n>" << std::endl;
        std::cout << "-t, --threads <n>" << std::endl;
        return 0;
    }

    if (config.syn_threads == 0)
        config.syn_threads = 1;
    if (config.threads == 0)
        config.threads = 1;
    if (config.duration == std::chrono::duration<double>(0))
        config.duration = std::chrono::duration<double>(std::chrono::seconds(10));

    Benckmark(config.syn_threads, config.threads, config.duration);
}
