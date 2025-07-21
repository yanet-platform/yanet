#include "benchmark.h"

#include <iostream>
#include <thread>
#include <vector>

#include "dataplane/globalbase.h"
#include "dataplane/metadata.h"
#include "dataplane/proxy.h"

const common::ipv4_prefix_t local_pool_prefix("33.0.0.0/24");
const uint32_t size_connections_table = 256;
const uint32_t size_syn_table = 32;

void InitializeProxyService(dataplane::proxy::TcpConnectionStore& tcp_connection_store, dataplane::base::generation& base, dataplane::proxy::proxy_service_t& service)
{
    uint32_t proxy_addr = rte_cpu_to_be_32(common::ipv4_address_t("22.0.0.1"));
    uint16_t proxy_port = rte_cpu_to_be_16(80);
    uint32_t upstream_addr = rte_cpu_to_be_32(common::ipv4_address_t("44.0.0.1"));
    uint16_t upstream_port = rte_cpu_to_be_16(8080);

    proxy_service_id_t service_id = 1;

    base.globalBase = new dataplane::globalBase::generation(nullptr, 0);
    dataplane::proxy::proxy_service_t service_cfg;

    service_cfg.service_id = service_id;
    service_cfg.proxy_addr = proxy_addr;
	service_cfg.proxy_port = proxy_port;
	service_cfg.upstream_addr = upstream_addr;
	service_cfg.upstream_port = upstream_port;
    service_cfg.pool_prefix.address.address = uint32_t(local_pool_prefix.address());
    service_cfg.pool_prefix.mask = local_pool_prefix.mask();
	service_cfg.counter_id = 0;
	service_cfg.send_proxy_header = false;
	service_cfg.size_connections_table = size_connections_table;
	service_cfg.size_syn_table = size_syn_table;
	service_cfg.use_sack = YANET_PROXY_DEFAULT_USE_SACK;
	service_cfg.mss = YANET_PROXY_DEFAULT_MSS;
	service_cfg.winscale = YANET_PROXY_DEFAULT_WINSCALE;
	service_cfg.timestamps = YANET_PROXY_DEFAULT_USE_TIMESTAMPS;

    uint8_t currentGlobalBaseId = 0;
    uint8_t newGlobalBaseId = currentGlobalBaseId ^ 1;

    base.globalBase->proxy_services[service_id] = service_cfg;

    tcp_connection_store.ServiceUpdate(service_cfg, nullptr, currentGlobalBaseId, true);
    tcp_connection_store.ServiceUpdate(service_cfg, nullptr, newGlobalBaseId, false);
    service = service_cfg;
    base.globalBase->proxy_services[service_id] = service_cfg;
    tcp_connection_store.current_time_sec = time(nullptr);
    tcp_connection_store.current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
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
}

void Benckmark(unsigned int syn_threads_num, unsigned int threads_num, std::chrono::duration<double> duration) {
    uint64_t duration_sec = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    std::cout << "Starting benchmark...\n";
    std::cout << "Syn threads: " << syn_threads_num << "\n";
    std::cout << "Threads: " << threads_num << "\n";
    std::cout << "Duration: " << duration_sec << "s\n";

    dataplane::proxy::TcpConnectionStore tcp_connection_store;
    dataplane::base::generation base;
    dataplane::proxy::proxy_service_t service;
    InitializeProxyService(tcp_connection_store, base, service);

    bool finished = false;
    std::thread ts_thread = std::thread([&]() {
        uint32_t prev_time = 0;
        while (!finished)
        {
            uint32_t current_time = time(nullptr);
            if (current_time != prev_time)
            {
                tcp_connection_store.current_time_sec = current_time;
                prev_time = current_time;
            }
            tcp_connection_store.current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    std::thread gc_thread = std::thread([&]() {
        while (!finished)
		{
			tcp_connection_store.CollectGarbage();
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
    });

    std::vector<rte_mbuf*> syn_mbufs(syn_threads_num);
    std::vector<rte_mbuf*> mbufs(threads_num);
    for (unsigned int i = 0; i < syn_threads_num; i++) {
        CreateMbuf(&syn_mbufs[i]);
    }
    for (unsigned int i = 0; i < threads_num; i++) {
        CreateMbuf(&mbufs[i]);
    }

    std::vector<std::thread> syn_threads;
    std::vector<std::thread> threads;
    std::vector<uint64_t> syn_iterations(syn_threads_num);
    std::vector<uint64_t> iterations(threads_num);
    for (unsigned int i = 0; i < syn_threads_num; i++) {
        syn_threads.emplace_back([=, &syn_mbufs, &syn_iterations, &base, &tcp_connection_store, &service]() {
            uint32_t client_addr = rte_cpu_to_be_32(common::ipv4_address_t("11.0.0.1") + i);
            std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
            uint64_t counters[64];
            rte_mbuf* mbuf = syn_mbufs[i];
            uint8_t tcp_options[] = {0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xb1, 0xcf, 0x1a, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x05, 0x01};
            for (uint32_t j = 0; ; j++)
            {
                if ((syn_iterations[i] & (1024 - 1)) == 0 && std::chrono::steady_clock::now() - start >= duration)
                    break;

                dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
                rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
                rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
                ipv4_header->src_addr = client_addr;
                ipv4_header->dst_addr = service.proxy_addr;
                tcp_header->src_port = rte_cpu_to_be_16(32768 + (j + i * 1024) % 32768);
                tcp_header->dst_port = service.proxy_port;
                tcp_header->data_off = 0xa0;
                memcpy((uint8_t*)tcp_header + sizeof(rte_tcp_hdr), tcp_options, 20);

                mbuf->buf_len = 100;
                mbuf->pkt_len = 100;

                metadata->flow.data.proxy_service_id = 1;

                tcp_connection_store.ActionClientOnSyn(mbuf, base, counters, i);
                syn_iterations[i]++;
            }
        });
    }

    dataplane::proxy::LocalPool local_pool;
    local_pool.Init(1, ipv4_prefix_t{local_pool_prefix.address(), local_pool_prefix.mask()}, nullptr);
    for (unsigned int i = 0; i < threads_num; i++) {
        threads.emplace_back([=, &local_pool, &mbufs, &iterations, &base, &tcp_connection_store, &service]() {
            uint32_t client_addr = rte_cpu_to_be_32(common::ipv4_address_t("11.0.1.0") + i);
            std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
            uint64_t counters[64];
            rte_mbuf* mbuf = mbufs[i];
            uint32_t local_addr;
            uint16_t local_port;

            uint32_t timestamp = 0xb1cf1a9a;
            dataplane::proxy::TcpOptions tcp_options;
            tcp_options.mss = 1460;
            tcp_options.window_scaling = 5;
            tcp_options.sack_permitted = true;
            tcp_options.timestamp_value = timestamp;
            for (uint32_t j = 0; ; j++)
            {
                if ((iterations[i] & (1024 - 1)) == 0 && std::chrono::steady_clock::now() - start >= duration)
                    break;

                uint16_t client_port = rte_cpu_to_be_16(32768 + (j + i * 1024) % 32768);
                dataplane::proxy::LocalPool::UnpackTuple(
                    local_pool.Allocate(i, client_addr, client_port), 
                    local_addr, local_port
                );

                dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
                metadata->flow.data.proxy_service_id = 1;

                rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
                rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
                ipv4_header->src_addr = client_addr;
                ipv4_header->dst_addr = service.proxy_addr;
                tcp_header->src_port = client_port;
                tcp_header->dst_port = service.proxy_port;
                tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                tcp_connection_store.ActionClientOnSyn(mbuf, base, counters, i);

                ipv4_header->src_addr = service.upstream_addr;
                ipv4_header->dst_addr = local_addr;
                tcp_header->src_port = service.upstream_port;
                tcp_header->dst_port = local_port;
                tcp_options.timestamp_value = timestamp + 1;
                tcp_options.timestamp_echo = timestamp;
                tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                tcp_connection_store.ActionServiceOnSynAck(mbuf, base, counters);

                ipv4_header->src_addr = client_addr;
                ipv4_header->dst_addr = service.proxy_addr;
                tcp_header->src_port = client_port;
                tcp_header->dst_port = service.proxy_port;
                tcp_options.mss = 0;
                tcp_options.window_scaling = 0;
                tcp_options.sack_permitted = false;
                tcp_options.timestamp_value = timestamp + 2;
                tcp_options.timestamp_echo = timestamp + 1;
                tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                tcp_connection_store.ActionClientOnAck(mbuf, base, counters, i);

                ipv4_header->src_addr = service.upstream_addr;
                ipv4_header->dst_addr = local_addr;
                tcp_header->src_port = service.upstream_port;
                tcp_header->dst_port = local_port;
                tcp_options.timestamp_value = timestamp + 3;
                tcp_options.timestamp_echo = timestamp + 2;
                tcp_options.WriteSYN(mbuf, ipv4_header, tcp_header);
                tcp_connection_store.ActionServiceOnAck(mbuf, base, counters);

                iterations[i]++;
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
    for (unsigned int i = 0; i < syn_threads_num; i++) {
        std::cout << i << ": " << syn_iterations[i] << " iterations\n";
    }
    std::cout << "Sum: " << std::accumulate(syn_iterations.begin(), syn_iterations.end(), 0) << " iterations\n";
    std::cout << "Threads:\n";
    for (unsigned int i = 0; i < threads_num; i++) {
        std::cout << i << ": " << iterations[i] << " iterations\n";
    }
    std::cout << "Sum: " << std::accumulate(iterations.begin(), iterations.end(), 0) << " iterations\n";
}