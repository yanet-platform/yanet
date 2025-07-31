#include "benchmark.h"

#include <iostream>
#include <thread>
#include <vector>

#include "dataplane/globalbase.h"
#include "dataplane/metadata.h"
#include "dataplane/proxy.h"
#include "common/ringlog.h"

const common::ipv4_prefix_t local_pool_prefix("33.0.0.0/24");
const uint32_t size_connections_table = 65536;
const uint32_t size_syn_table = 1024;
const common::ipv4_address_t proxy_addr("22.0.0.1");
const uint16_t proxy_port = rte_cpu_to_be_16(80);
const common::ipv4_address_t upstream_addr("44.0.0.1");
const uint16_t upstream_port = rte_cpu_to_be_16(8080);
common::ringlog::LogInfo ringlog;

void InitializeProxyService(dataplane::proxy::TcpConnectionStore& tcp_connection_store, dataplane::base::generation& base, proxy_service_id_t service_id)
{
    base.globalBase = new dataplane::globalBase::generation(nullptr, 0);
    controlplane::proxy::service_t service_cfg;

    service_cfg.service_id = service_id;
    service_cfg.proxy_addr = proxy_addr;
	service_cfg.proxy_port = proxy_port;
	service_cfg.upstream_addr = upstream_addr;
	service_cfg.upstream_port = upstream_port;
    service_cfg.upstream_nets.push_back(local_pool_prefix);
	service_cfg.send_proxy_header = false;
	service_cfg.size_connections_table = size_connections_table;
	service_cfg.size_syn_table = size_syn_table;
	service_cfg.tcp_options.use_sack = YANET_PROXY_DEFAULT_USE_SACK;
	service_cfg.tcp_options.mss = YANET_PROXY_DEFAULT_MSS;
	service_cfg.tcp_options.winscale = YANET_PROXY_DEFAULT_WINSCALE;
	service_cfg.tcp_options.timestamps = YANET_PROXY_DEFAULT_USE_TIMESTAMPS;
    service_cfg.timeouts.syn_recv = YANET_PROXY_DEFAULT_TIMEOUT_SYN_RECV;
    service_cfg.timeouts.established = YANET_PROXY_DEFAULT_TIMEOUT_ESTABLISHED;

    dataplane::proxy::proxy_service_t& service = base.globalBase->proxy_services[service_id];

    tcp_connection_store.ActivateSocket(0);
    tcp_connection_store.ServiceUpdateOnSocket(0, service, 0, service_cfg, true, nullptr);
    tcp_connection_store.ServiceUpdateOnSocket(0, service, 0, service_cfg, false, nullptr);

    ringlog.records = new common::ringlog::LogRecord[64];
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

void Benchmark(const Config& config) {
    uint64_t duration_sec = std::chrono::duration_cast<std::chrono::seconds>(config.duration).count();
    std::cout << "Starting benchmark...\n";
    std::cout << "Syn threads: " << config.syn_threads << "\n";
    std::cout << "Threads: " << config.threads << "\n";
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
    std::vector<uint64_t> syn_iterations(config.syn_threads);
    std::vector<uint64_t> iterations(config.threads);

    uint64_t synflood_syn_dropped = 0;
    uint64_t synflood_synack_dropped = 0;

    uint32_t worker_id = 0;
    for (unsigned int i = 0; i < config.syn_threads; i++, worker_id++) {
        syn_threads.emplace_back([=, &current_time, &current_time_ms, &synflood_syn_dropped, &synflood_synack_dropped, &syn_mbufs, &syn_iterations, &base, &tcp_connection_store, &service]() {
            uint32_t client_addr = rte_cpu_to_be_32(common::ipv4_address_t("11.0.0.1") + i);
            std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
            uint64_t counters[64];
            rte_mbuf* mbuf = syn_mbufs[i];

            uint32_t local_addr;
            uint16_t local_port;

            uint32_t timestamp = 0xb1cf1a9a;
            dataplane::proxy::TcpOptions tcp_options;
            tcp_options.mss = 1460;
            tcp_options.window_scaling = 5;
            tcp_options.sack_permitted = true;
            tcp_options.timestamp_value = timestamp;
            for (uint64_t j = 0; ; j++)
            {
                if ((j & (1024 - 1)) == 0 && std::chrono::steady_clock::now() - start >= config.duration)
                    break;
                if (config.synflood_packets && j == config.synflood_packets) break;

                dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
                rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
                rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);

                SetIPAddresses(ipv4_header, client_addr, service.config.proxy_addr);
                SetTCPPorts(tcp_header, rte_cpu_to_be_16(32768 + j % 32768), service.config.proxy_port);
                SetSeqAck(tcp_header, 0, 0);
                tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                if (!tcp_connection_store.ActionClientOnSyn(mbuf, base, counters, worker_id, ringlog, current_time, current_time_ms))
                { // packet dropped
                    synflood_syn_dropped++;
                    continue;
                }

                if (ipv4_header->dst_addr != client_addr) // not cookie
                {
                    local_addr = ipv4_header->src_addr;
                    local_port = tcp_header->src_port;

                    SetIPAddresses(ipv4_header, service.config.upstream_addr, local_addr);
                    SetTCPPorts(tcp_header, service.config.upstream_port, local_port);
                    SetSeqAck(tcp_header, 0, rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionServiceOnSynAck(mbuf, base, counters, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        synflood_synack_dropped++;
                        break;
                    }
                }

                syn_iterations[i]++;
            }
        });
    }

    uint64_t client_syn_dropped = 0;
    uint64_t client_ack_dropped = 0;
    uint64_t server_synack_dropped = 0;
    uint64_t server_ack_dropped = 0;

    for (unsigned int i = 0; i < config.threads; i++, worker_id++) {
        threads.emplace_back([=, &current_time, &current_time_ms, &client_syn_dropped, &client_ack_dropped, &server_synack_dropped, &server_ack_dropped, &mbufs, &iterations, &base, &tcp_connection_store, &service]() {
            uint32_t client_addr = rte_cpu_to_be_32(common::ipv4_address_t("11.0.1.1") + i);
            std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
            uint64_t counters[64];
            rte_mbuf* mbuf = mbufs[i];
            uint32_t local_addr;
            uint16_t local_port;

            uint32_t timestamp = 0xb1cf1a9a;
            uint32_t server_seq = 0;
            uint32_t client_seq = 0xf0000000;
            dataplane::proxy::TcpOptions tcp_options;
            for (uint32_t j = 0; ; j++)
            {
                if ((j & (1024 - 1)) == 0 && std::chrono::steady_clock::now() - start >= config.duration)
                break;
                
                uint16_t client_port = rte_cpu_to_be_16(32768 + j % 32768);
                
                dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
                rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
                rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
                SetIPAddresses(ipv4_header, client_addr, service.config.proxy_addr);
                SetTCPPorts(tcp_header, client_port, service.config.proxy_port);
                SetSeqAck(tcp_header, client_seq, 0);
                tcp_options.mss = 1460;
                tcp_options.window_scaling = 5;
                tcp_options.sack_permitted = true;
                tcp_options.timestamp_value = timestamp;
                tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                if (!tcp_connection_store.ActionClientOnSyn(mbuf, base, counters, worker_id, ringlog, current_time, current_time_ms))
                { // packet dropped
                    client_syn_dropped++;
                    continue;
                }

                if (ipv4_header->dst_addr == client_addr) // syn cookie
                {
                    SetIPAddresses(ipv4_header, client_addr, service.config.proxy_addr);
                    SetTCPPorts(tcp_header, client_port, service.config.proxy_port);
                    SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    tcp_options.Clear();
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionClientOnAck(mbuf, base, counters, worker_id, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        client_ack_dropped++;
                        continue;
                    }

                    // ClientOnAck moves packet headers when writing options
                    ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
                    tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
                    local_addr = ipv4_header->src_addr;
                    local_port = tcp_header->src_port;
                    
                    ResetMbuf(mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
                    SetIPAddresses(ipv4_header, service.config.upstream_addr, local_addr);
                    SetTCPPorts(tcp_header, service.config.upstream_port, local_port);
                    SetSeqAck(tcp_header, server_seq, rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    tcp_options.Clear();
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionServiceOnSynAck(mbuf, base, counters, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        server_synack_dropped++;
                        continue;
                    }

                    SetIPAddresses(ipv4_header, client_addr, service.config.proxy_addr);
                    SetTCPPorts(tcp_header, client_port, service.config.proxy_port);
                    SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    tcp_options.Clear();
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionClientOnAck(mbuf, base, counters, worker_id, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        client_ack_dropped++;
                        continue;
                    }

                    ResetMbuf(mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
                    SetIPAddresses(ipv4_header, service.config.upstream_addr, local_addr);
                    SetTCPPorts(tcp_header, service.config.upstream_port, local_port);
                    SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionServiceOnAck(mbuf, base, counters, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        server_ack_dropped++;
                        continue;
                    }
                }
                else if (ipv4_header->dst_addr == upstream_addr) // normal flow
                {
                    local_addr = ipv4_header->src_addr;
                    local_port = tcp_header->src_port;

                    SetIPAddresses(ipv4_header, service.config.upstream_addr, local_addr);
                    SetTCPPorts(tcp_header, service.config.upstream_port, local_port);
                    SetSeqAck(tcp_header, server_seq, rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionServiceOnSynAck(mbuf, base, counters, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        server_synack_dropped++;
                        continue;
                    }
    
                    SetIPAddresses(ipv4_header, client_addr, service.config.proxy_addr);
                    SetTCPPorts(tcp_header, client_port, service.config.proxy_port);
                    SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    tcp_options.Clear();
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionClientOnAck(mbuf, base, counters, worker_id, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        client_ack_dropped++;
                        continue;
                    }
    
                    ResetMbuf(mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
                    SetIPAddresses(ipv4_header, service.config.upstream_addr, local_addr);
                    SetTCPPorts(tcp_header, service.config.upstream_port, local_port);
                    SetSeqAck(tcp_header, rte_be_to_cpu_32(tcp_header->recv_ack), rte_be_to_cpu_32(tcp_header->sent_seq) + 1);
                    AdvanceTS(tcp_options, timestamp);
                    tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                    if (!tcp_connection_store.ActionServiceOnAck(mbuf, base, counters, ringlog, current_time, current_time_ms))
                    { // packet dropped
                        server_ack_dropped++;
                        continue;
                    }
                }

                iterations[i]++;
                ResetMbuf(mbuf, &ipv4_header, &tcp_header); // TODO: Should probably just move headers back
            }
        });
    }

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
    for (unsigned int i = 0; i < config.syn_threads; i++) {
        std::cout << i << ": " << syn_iterations[i] << " iterations\n";
    }
    std::cout << "Sum: " << std::accumulate(syn_iterations.begin(), syn_iterations.end(), 0) << " iterations\n";
    std::cout << "synflood_syn_dropped: " << synflood_syn_dropped << std::endl;
    std::cout << "synflood_synack_dropped: " << synflood_synack_dropped << std::endl;

    std::cout << "\nThreads:\n";
    for (unsigned int i = 0; i < config.threads; i++) {
        std::cout << i << ": " << iterations[i] << " iterations\n";
    }
    std::cout << "Sum: " << std::accumulate(iterations.begin(), iterations.end(), 0) << " iterations\n";
    std::cout << "client_syn_dropped: " << client_syn_dropped << std::endl;
    std::cout << "server_synack_dropped: " << server_synack_dropped << std::endl;
    std::cout << "client_ack_dropped: " << client_ack_dropped << std::endl;
    std::cout << "server_ack_dropped: " << server_ack_dropped << std::endl;
}