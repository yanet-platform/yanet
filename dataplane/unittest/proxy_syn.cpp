#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <future>
#include <thread>
#include <rte_mbuf.h>

#include "../globalbase.h"
#include "../metadata.h"
#include "../proxy.h"

void InitializeProxyService(dataplane::proxy::TcpConnectionStore& tcp_connection_store, dataplane::base::generation& base, dataplane::proxy::proxy_service_t& service)
{
    uint32_t proxy_addr = rte_cpu_to_be_32(common::ipv4_address_t("22.0.0.1"));
    uint16_t proxy_port = rte_cpu_to_be_16(80);
    uint32_t upstream_addr = rte_cpu_to_be_32(common::ipv4_address_t("44.0.0.1"));
    uint16_t upstream_port = rte_cpu_to_be_16(8080);
    common::ipv4_prefix_t local_pool_prefix("33.0.0.0/24");
    uint32_t size_connections_table = 256;
    uint32_t size_syn_table = 32;

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

    ASSERT_EQ(tcp_connection_store.ServiceUpdate(service_cfg, nullptr, currentGlobalBaseId, true), eResult::success);
    ASSERT_EQ(tcp_connection_store.ServiceUpdate(service_cfg, nullptr, newGlobalBaseId, false), eResult::success);
    service = service_cfg;
    base.globalBase->proxy_services[service_id] = service_cfg;
    tcp_connection_store.current_time_sec = time(nullptr);
    tcp_connection_store.current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void CreateMbuf(rte_mbuf** mbuf)
{
    *mbuf = new rte_mbuf();
    ASSERT_TRUE(*mbuf != nullptr);
    rte_pktmbuf_reset(*mbuf);
    (*mbuf)->buf_addr = malloc(10240);
    memset((*mbuf)->buf_addr, 0, 10240);
    ASSERT_NE((*mbuf)->buf_addr, nullptr);
    dataplane::metadata* metadata = YADECAP_METADATA(*mbuf);
    metadata->network_headerOffset = 18;
    metadata->transport_headerOffset = 38;
}

TEST(ServiceSynConnectionsTest, SynFlood)
{
    uint32_t threads_count = 4;
    uint32_t packets_count = 10000;
    uint32_t client_addr = rte_cpu_to_be_32(common::ipv4_address_t("11.0.0.1"));

    dataplane::proxy::TcpConnectionStore tcp_connection_store;
    dataplane::base::generation base;
    dataplane::proxy::proxy_service_t service;
	InitializeProxyService(tcp_connection_store, base, service);

    std::vector<rte_mbuf*> mbufs(threads_count);
    for (uint32_t index = 0; index < threads_count; index++)
    {
        CreateMbuf(&mbufs[index]);
    }

    std::vector<std::thread> threads;
    for (uint32_t index = 0; index < threads_count; index++)
    {
        uint32_t worker_id = index;
        threads.emplace_back([&mbufs, &base, &tcp_connection_store, &service, client_addr, worker_id, packets_count, index]() {
            uint64_t counters[64];
            rte_mbuf* mbuf = mbufs[index];
            for (uint32_t packet_index = 0; packet_index < packets_count; packet_index++)
            {
                // if (packet_index % 1000 == 0)
                // {
                //     std::cout << "Work thread " << index << ", packet: " << packet_index << std::endl;
                // }
                dataplane::metadata* metadata = YADECAP_METADATA(mbuf);
                // metadata->flow.data.proxy_service_id = 1;
                rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(mbuf, rte_ipv4_hdr*, metadata->network_headerOffset);
                rte_tcp_hdr* tcp_header = rte_pktmbuf_mtod_offset(mbuf, rte_tcp_hdr*, metadata->transport_headerOffset);
                ipv4_header->src_addr = client_addr;
                ipv4_header->dst_addr = service.proxy_addr;
                tcp_header->src_port = rte_cpu_to_be_16(32768 + (packet_index + index * 1024) % 32768);
                tcp_header->dst_port = service.proxy_port;
                tcp_header->data_off = 0xa0;
                uint8_t tcp_options[] = {0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xb1, 0xcf, 0x1a, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x05, 0x01};
                for (int i = 0; i < 20; i++)
                {
                    *(((uint8_t*)tcp_header) + sizeof(rte_tcp_hdr) + i) = tcp_options[i];
                }

                mbuf->buf_len = 100;
                mbuf->pkt_len = 100;

                metadata->flow.data.proxy_service_id = 1;
                ASSERT_TRUE(tcp_connection_store.ActionClientOnSyn(mbuf, base, counters, worker_id));
            }
        });
    }

    for (uint32_t index = 0; index < threads_count; index++)
    {
        threads[index].join();
    }
}

TEST(ServiceSynConnectionsTest, Benchmark)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    const int samples = 64;
    const int iterations = 8'000'000;
    std::array<std::chrono::duration<double>, samples> find;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    for (int s = 0; s < samples; s += concurrency)
    {
        for (unsigned int j = s; j < s + concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                dataplane::proxy::ServiceSynConnections syn;
                syn.Init(1, iterations, nullptr, 0, 0);
            
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < iterations; i++)
                {
                    dataplane::proxy::ConnectionData<dataplane::proxy::SynConnection> data;
                    syn.FindAndLock(i, 2, 6, data);
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
            
                return find_elapsed;
            });
        }
        for (unsigned int i = s; i < s + concurrency && i < samples; i++)
        {
            find[i] = futures[i].get();
        }
    }

    std::sort(find.begin(), find.end());

    std::cout << "Samples: " << samples << " (Concurrent: " << concurrency << ")\nIterations: " << iterations << "\n";
    std::cout << "FindAndLock:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() / 2]).count() << "ms\n";
}

TEST(ServiceSynConnectionsTest, BenchmarkConcurrent)
{
    unsigned int concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0)
    {
        concurrency = 8;
    }
    unsigned int sample_concurrency = std::sqrt(concurrency);
    unsigned int access_concurrency = sample_concurrency;

    const unsigned int samples = 64;
    const unsigned int iterations = 8'000'000;
    unsigned int iter_per_future = iterations / access_concurrency;
    std::array<std::chrono::duration<double>, samples> find;
    std::array<std::future<std::chrono::duration<double>>, samples> futures;
    std::cout << "Samples: " << samples << " (Concurrent: " << sample_concurrency 
              << ")\nIterations: " << iterations << " (Concurrent: " << access_concurrency << ")\n";
    for (unsigned int s = 0; s < samples; s += sample_concurrency)
    {
        for (unsigned int j = s; j < s + sample_concurrency && j < samples; j++)
        {
            futures[j] = std::async(std::launch::async, [&]() -> std::chrono::duration<double> {
                dataplane::proxy::ServiceSynConnections syn;
                syn.Init(1, iterations, nullptr, 0, 0);
            
                std::vector<std::future<void>> fs(access_concurrency);
                std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
                for (unsigned int i = 0; i < access_concurrency; i++)
                {
                    fs[i] = std::async(std::launch::async, [=, &syn]() {
                        unsigned int start = i * iter_per_future;
                        for (unsigned int k = start; k < start + iter_per_future; k++)
                        {
                            dataplane::proxy::ConnectionData<dataplane::proxy::SynConnection> data;
                            syn.FindAndLock(k, 2, 6, data);
                        }
                    });
                }
                for (auto& f : fs)
                {
                    f.get();
                }
                auto find_elapsed = std::chrono::steady_clock::now() - start;
    
                return find_elapsed;
            });
        }
        for (unsigned int i = s; i < s + sample_concurrency && i < samples; i++)
        {
            find[i] = futures[i].get();
        }
    }

    std::sort(find.begin(), find.end());

    std::cout << "FindAndLock:\n\tmin: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[0]).count()
              << "ms, max: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() - 1]).count()
              << "ms, mean: " << std::chrono::duration_cast<std::chrono::milliseconds>(find[find.size() / 2]).count() << "ms\n";
}
