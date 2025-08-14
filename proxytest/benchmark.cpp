#include "benchmark.h"

#include <iostream>
#include <thread>
#include <vector>
#include <condition_variable>
#include <mutex>
#include <pthread.h>

#include "dataplane/metadata.h"
#include "common/counters.h"
#include "common/ringlog.h"

const common::ipv4_prefix_t local_pool_prefix("33.0.0.0/24");
const uint32_t size_connections_table = 2 << 24;
const uint32_t size_syn_table = 1024;
const common::ipv4_address_t proxy_addr("22.0.0.1");
const uint16_t proxy_port = rte_cpu_to_be_16(80);
const common::ipv4_address_t upstream_addr("44.0.0.1");
const uint16_t upstream_port = rte_cpu_to_be_16(8080);
common::ringlog::LogInfo ringlog;

dataplane::proxy::proxy_service_config_t GetProxyConfig()
{
    proxy_service_id_t service_id = 1;

    dataplane::proxy::proxy_service_config_t service_config {
        .service_id = service_id,
	    .counter_id = 0,
        .proxy_addr = proxy_addr,
	    .proxy_port = proxy_port,
	    .upstream_addr = upstream_addr,
	    .upstream_port = upstream_port,
	    .size_connections_table = size_connections_table,
	    .size_syn_table = size_syn_table,
        .pool_prefix {
            .address = uint32_t(local_pool_prefix.address()),
            .mask = local_pool_prefix.mask(),
        },
	    .send_proxy_header = false,
	    .tcp_options = {
            .use_sack = YANET_PROXY_DEFAULT_USE_SACK,
	        .mss = YANET_PROXY_DEFAULT_MSS,
	        .winscale = YANET_PROXY_DEFAULT_WINSCALE,
	        .timestamps = YANET_PROXY_DEFAULT_USE_TIMESTAMPS,
        },
        .timeouts = {
            .syn_rto = YANET_PROXY_DEFAULT_TIMEOUT_SYN_RTO,
            .syn_recv = YANET_PROXY_DEFAULT_TIMEOUT_SYN_RECV,
            .established = YANET_PROXY_DEFAULT_TIMEOUT_ESTABLISHED,
        },
        .debug_flags = 0,
    };

    return service_config;
}

void InitializeProxyService(dataplane::proxy::TcpConnectionStore& tcp_connection_store, dataplane::base::generation& base, proxy_service_id_t service_id)
{
    tSocketId socket_id = 0;

    base.globalBase = new dataplane::globalBase::generation(nullptr, 0);
    base.globalBase->proxy_services[service_id].config = GetProxyConfig();
    base.globalBase->proxy_services[service_id].UpdateProxyHeader();

    tcp_connection_store.ActivateSocket(socket_id);
    tcp_connection_store.ServiceUpdateOnSocket(socket_id, base.globalBase->proxy_services[service_id], true, nullptr);
    tcp_connection_store.ServiceUpdateOnSocket(socket_id, base.globalBase->proxy_services[service_id], false, nullptr);
}

inline void ResetMbuf(rte_mbuf* mbuf, rte_ipv4_hdr** ipv4_header, rte_tcp_hdr** tcp_header)
{
    rte_pktmbuf_reset(mbuf);
    mbuf->data_off = 256;
    memset(mbuf->buf_addr, 0, 10240);
    dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
    metadata->network_headerOffset = 18;
    metadata->transport_headerOffset = 38;
    metadata->flow.data.proxy_service_id = 1;
    *ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
    *tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
}

void CreateMbuf(rte_mbuf** mbuf)
{
    *mbuf = new rte_mbuf();
    rte_pktmbuf_reset(*mbuf);
    (*mbuf)->buf_addr = malloc(10240);
    memset((*mbuf)->buf_addr, 0, 10240);
    (*mbuf)->data_off = 256;
    dataplane::metadata* metadata = YADECAP_METADATA(*mbuf);
    metadata->network_headerOffset = 18;
    metadata->transport_headerOffset = 38;
    metadata->flow.data.proxy_service_id = 1;
}

inline void SetIPAddresses(rte_ipv4_hdr* ipv4_header, uint32_t src_addr, uint32_t dst_addr)
{
    ipv4_header->src_addr = src_addr;
    ipv4_header->dst_addr = dst_addr;
}

inline void SetTCPPorts(rte_tcp_hdr* tcp_header, uint16_t src_port, uint16_t dst_port)
{
    tcp_header->src_port = src_port;
    tcp_header->dst_port = dst_port;
}

inline void SetSeqAck(rte_tcp_hdr* tcp_header, uint32_t seq, uint32_t ack)
{
    tcp_header->sent_seq = rte_cpu_to_be_32(seq);
    tcp_header->recv_ack = rte_cpu_to_be_32(ack);
}

inline void AdvanceTS(dataplane::proxy::TcpOptions& tcp_options, uint32_t& timestamp){
    tcp_options.timestamp_echo = timestamp++;
    tcp_options.timestamp_value = timestamp;
}

std::shared_mutex thread_sync_mutex;
std::condition_variable_any thread_sync_cv;
bool thread_sync_ready = false;

void SynFlow(uint32_t worker_id, const Config& config, WorkerArgs args, uint32_t i)
{
    uint32_t client_addr = rte_cpu_to_be_32(common::ipv4_address_t("11.0.0.1") + i);
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    uint32_t local_addr;
    uint16_t local_port;

    uint32_t timestamp = 0xb1cf1a9a;
    dataplane::proxy::TcpOptions tcp_options;
    tcp_options.mss = 1460;
    tcp_options.window_scaling = 5;
    tcp_options.sack_permitted = true;
    tcp_options.timestamp_value = timestamp;

    std::shared_lock lock(thread_sync_mutex);
    thread_sync_cv.wait(lock, [&] { return thread_sync_ready; });

    for (uint64_t j = 0; ; j++)
    {
        if ((j & (1024 - 1)) == 0 && std::chrono::steady_clock::now() - start >= config.duration)
            break;
        if (config.synflood_packets && j == config.synflood_packets) break;

        dataplane::metadata* metadata = YADECAP_METADATA(args.mbuf);
        rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(args.mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
        rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(args.mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);

        SetIPAddresses(ipv4_header, client_addr, args.service->config.proxy_addr);
        SetTCPPorts(tcp_header, rte_cpu_to_be_16(32768 + j % 32768), args.service->config.proxy_port);
        SetSeqAck(tcp_header, 0, 0);
        tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
        dataplane::proxy::WorkerInfo worker_info{
            .globalBase = args.base->globalBase,
            .counters = args.stats->counters,
            .worker_id = worker_id,
            .ringlog = &ringlog,
            .current_time_sec = *args.current_time,
            .current_time_ms = *args.current_time_ms,
        };
        if (!dataplane::proxy::ActionClientOnSyn(args.mbuf, worker_info))
        { // packet dropped
            args.stats->client_syn_dropped++;
            continue;
        }

        if (ipv4_header->dst_addr != client_addr) // not cookie
        {
            local_addr = ipv4_header->src_addr;
            local_port = tcp_header->src_port;

            SetIPAddresses(ipv4_header, args.service->config.upstream_addr, local_addr);
            SetTCPPorts(tcp_header, args.service->config.upstream_port, local_port);
            SetSeqAck(tcp_header, 0, rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionServiceOnSynAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->server_synack_dropped++;
                break;
            }
        }

        args.stats->iterations[i]++;
    }
}

void NormalFlow(uint32_t worker_id, const Config& config, WorkerArgs args, uint32_t i)
{
    uint32_t client_addr = rte_cpu_to_be_32(common::ipv4_address_t("11.0.1.1") + i);
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    uint32_t local_addr;
    uint16_t local_port;

    uint32_t timestamp = 0xb1cf1a9a;
    uint32_t server_seq = 0;
    uint32_t client_seq = 0xf0000000;   
    dataplane::proxy::TcpOptions tcp_options;

    std::shared_lock lock(thread_sync_mutex);
    thread_sync_cv.wait(lock, [&] { return thread_sync_ready; });

    for (uint32_t j = 0; ; j++)
    {
        if ((j & (1024 - 1)) == 0 && std::chrono::steady_clock::now() - start >= config.duration)
            break;
        
        uint16_t client_port = rte_cpu_to_be_16(32768 + j % 32768);
        
        dataplane::metadata* metadata = YADECAP_METADATA(args.mbuf);
        rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(args.mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
        rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(args.mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
        SetIPAddresses(ipv4_header, client_addr, args.service->config.proxy_addr);
        SetTCPPorts(tcp_header, client_port, args.service->config.proxy_port);
        SetSeqAck(tcp_header, client_seq, 0);
        tcp_options.mss = 1460;
        tcp_options.window_scaling = 5;
        tcp_options.sack_permitted = true;
        tcp_options.timestamp_value = timestamp;
        tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
        dataplane::proxy::WorkerInfo worker_info{
            .globalBase = args.base->globalBase,
            .counters = args.stats->counters,
            .worker_id = worker_id,
            .ringlog = &ringlog,
            .current_time_sec = *args.current_time,
            .current_time_ms = *args.current_time_ms,
        };
        if (!dataplane::proxy::ActionClientOnSyn(args.mbuf, worker_info))
        { // packet dropped
            args.stats->client_syn_dropped++;
            continue;
        }

        if (ipv4_header->dst_addr == client_addr) // syn cookie
        {
            SetIPAddresses(ipv4_header, client_addr, args.service->config.proxy_addr);
            SetTCPPorts(tcp_header, client_port, args.service->config.proxy_port);
            SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            tcp_options.Clear();
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionClientOnAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->client_ack_dropped++;
                continue;
            }

            // ClientOnAck moves packet headers when writing options
            ipv4_header = rte_pktmbuf_mtod_offset(args.mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
            tcp_header = rte_pktmbuf_mtod_offset(args.mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
            local_addr = ipv4_header->src_addr;
            local_port = tcp_header->src_port;
            
            ResetMbuf(args.mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
            SetIPAddresses(ipv4_header, args.service->config.upstream_addr, local_addr);
            SetTCPPorts(tcp_header, args.service->config.upstream_port, local_port);
            SetSeqAck(tcp_header, server_seq, rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            tcp_options.Clear();
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionServiceOnSynAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->server_synack_dropped++;
                continue;
            }

            SetIPAddresses(ipv4_header, client_addr, args.service->config.proxy_addr);
            SetTCPPorts(tcp_header, client_port, args.service->config.proxy_port);
            SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            tcp_options.Clear();
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionClientOnAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->client_ack_dropped++;
                continue;
            }

            ResetMbuf(args.mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
            SetIPAddresses(ipv4_header, args.service->config.upstream_addr, local_addr);
            SetTCPPorts(tcp_header, args.service->config.upstream_port, local_port);
            SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionServiceOnAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->server_ack_dropped++;
                continue;
            }
        }
        else if (ipv4_header->dst_addr == upstream_addr) // normal flow
        {
            local_addr = ipv4_header->src_addr;
            local_port = tcp_header->src_port;

            SetIPAddresses(ipv4_header, args.service->config.upstream_addr, local_addr);
            SetTCPPorts(tcp_header, args.service->config.upstream_port, local_port);
            SetSeqAck(tcp_header, server_seq, rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionServiceOnSynAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->server_synack_dropped++;
                continue;
            }

            SetIPAddresses(ipv4_header, client_addr, args.service->config.proxy_addr);
            SetTCPPorts(tcp_header, client_port, args.service->config.proxy_port);
            SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            tcp_options.Clear();
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionClientOnAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->client_ack_dropped++;
                continue;
            }

            ResetMbuf(args.mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
            SetIPAddresses(ipv4_header, args.service->config.upstream_addr, local_addr);
            SetTCPPorts(tcp_header, args.service->config.upstream_port, local_port);
            SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
            AdvanceTS(tcp_options, timestamp);
            tcp_options.WriteSYN(args.mbuf, ipv4_header, tcp_header);
            worker_info.current_time_sec = *args.current_time;
            worker_info.current_time_ms = *args.current_time_ms;
            if (!dataplane::proxy::ActionServiceOnAck(args.mbuf, worker_info))
            { // packet dropped
                args.stats->server_ack_dropped++;
                continue;
            }
        }

        args.stats->iterations[i]++;
        ResetMbuf(args.mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
    }
}

void Benchmark(const Config& config) {
    uint64_t duration_sec = std::chrono::duration_cast<std::chrono::seconds>(config.duration).count();
    std::cout << "Starting benchmark...\n";
    std::cout << "Syn threads: " << config.syn_threads << "\n";
    if (config.syn_cores.size() > 0)
    {
        std::cout << "Syn cores: ";
        for (auto& core : config.syn_cores)
        {
            std::cout << core << " ";
        }
        std::cout << "\n";
    }
    std::cout << "Threads: " << config.threads << "\n";
    if (config.cores.size() > 0)
    {
        std::cout << "Cores: ";
        for (auto& core : config.cores)
        {
            std::cout << core << " ";
        }
        std::cout << "\n";
    }
    std::cout << "Duration: " << duration_sec << "s\n";

    dataplane::proxy::TcpConnectionStore tcp_connection_store;
    dataplane::base::generation base;
    proxy_service_id_t service_id = 1;
    InitializeProxyService(tcp_connection_store, base, service_id);
    dataplane::proxy::proxy_service_t& service = base.globalBase->proxy_services[service_id];
    
    uint32_t current_time = time(nullptr);
    uint64_t current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    
    bool finished = false;
    std::thread ts_thread = std::thread([&]() {
        uint32_t prev_time = 0;
        while (!finished)
        {
            uint32_t current_time = time(nullptr);
            if (current_time != prev_time)
            {
                current_time = current_time;
                prev_time = current_time;
            }
            current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    std::thread gc_thread = std::thread([&]() {
        while (!finished)
		{
            tcp_connection_store.CollectGarbage(0, current_time_ms);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
    });
    
    std::vector<rte_mbuf*> syn_mbufs(config.syn_threads);
    std::vector<rte_mbuf*> mbufs(config.threads);
    for (unsigned int i = 0; i < config.syn_threads; i++) {
        CreateMbuf(&syn_mbufs[i]);
    }
    for (unsigned int i = 0; i < config.threads; i++) {
        CreateMbuf(&mbufs[i]);
    }
    
    std::vector<std::thread> syn_threads;
    std::vector<std::thread> threads;
    
    Stats syn_stats{};
    syn_stats.iterations = std::vector(config.syn_threads, uint64_t(0));
    Stats stats{};
    stats.iterations = std::vector(config.threads, uint64_t(0));
    
    WorkerArgs args = {};
    args.tcp_connection_store = &tcp_connection_store;
    args.base = &base;
    args.service = &service;
    args.current_time = &current_time;
    args.current_time_ms = &current_time_ms;
    bool cores = !config.syn_cores.empty() && !config.cores.empty();
    uint32_t worker_id = 0;
    args.stats = &syn_stats;
    for (unsigned int i = 0; i < config.syn_threads; i++, worker_id++) {
        args.mbuf = syn_mbufs[i];
        syn_threads.emplace_back(SynFlow, worker_id, std::cref(config), args, i);
        if (cores)
        {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(config.syn_cores[i], &cpuset);
            int rc = pthread_setaffinity_np(syn_threads[i].native_handle(), sizeof(cpu_set_t), &cpuset);
            if (rc != 0) {
                YANET_LOG_ERROR("Failed to set affinity for syn thread %d: %s\n", i, strerror(rc));
            }
        }
    }
    args.stats = &stats;
    for (unsigned int i = 0; i < config.threads; i++, worker_id++) {
        args.mbuf = mbufs[i];
        threads.emplace_back(NormalFlow, worker_id, std::cref(config), args, i);
        if (cores)
        {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(config.cores[i], &cpuset);
            int rc = pthread_setaffinity_np(threads[i].native_handle(), sizeof(cpu_set_t), &cpuset);
            if (rc != 0) {
                YANET_LOG_ERROR("Failed to set affinity for thread %d: %s\n", i, strerror(rc));
            }
        }
    }
    {
        std::lock_guard lock(thread_sync_mutex);
        thread_sync_ready = true;
    }
    thread_sync_cv.notify_all();

    for (uint64_t i = 0; i <= duration_sec; i++)
    {
        std::cout << "\rElapsed: " << i << "/" << duration_sec << "s";
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "\r\n";

    finished = true;
    for (auto& thread : syn_threads) {
        thread.join();
    }
    for (auto& thread : threads) {
        thread.join();
    }
    ts_thread.join();
    gc_thread.join();

    std::cout << "Benchmark finished\n";
    std::cout << "Syn threads:\n";
    for (unsigned int i = 0; i < syn_stats.iterations.size(); i++) {
        std::cout << i << ": " << syn_stats.iterations[i] << " iterations\n";
    }
    std::cout << "Sum: " << std::accumulate(syn_stats.iterations.begin(), syn_stats.iterations.end(), 0) << " iterations\n";
    std::cout << "SYNs dropped: " << syn_stats.client_syn_dropped << std::endl;
    std::cout << "SYNACKs dropped: " << syn_stats.server_synack_dropped << std::endl;
    std::cout << "counters:\n";
    for (uint32_t i = 0; i < ::proxy::names.size(); i++)
    {
        std::cout << "\t" << ::proxy::names[i] << ": " << syn_stats.counters[i] << "\n";
    }

    std::cout << "\nThreads:\n";
    for (unsigned int i = 0; i < stats.iterations.size(); i++) {
        std::cout << i << ": " << stats.iterations[i] << " iterations\n";
    }
    std::cout << "Sum: " << std::accumulate(stats.iterations.begin(), stats.iterations.end(), 0) << " iterations\n";
    std::cout << "Client SYNs dropped: " << stats.client_syn_dropped << std::endl;
    std::cout << "Server SYNACKs dropped: " << stats.server_synack_dropped << std::endl;
    std::cout << "Client ACKs dropped: " << stats.client_ack_dropped << std::endl;
    std::cout << "Server ACKs dropped: " << stats.server_ack_dropped << std::endl;
    std::cout << "counters:\n";
    for (uint32_t i = 0; i < ::proxy::names.size(); i++)
    {
        std::cout << "\t" << ::proxy::names[i] << ": " << stats.counters[i] << "\n";
    }
}