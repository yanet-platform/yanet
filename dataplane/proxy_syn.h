#pragma once

#include "memory_manager.h"
#include "type.h"

#include <mutex>

namespace dataplane::proxy
{

struct OneSynConnection
{
    uint64_t client;    // client ip + port
    uint64_t local;     // local ip + port
    uint32_t recv_seq;  // seq received from client
    uint32_t last_time; // time of last packet
    bool server_answer; // was received answer from server
    
    void Clear();
};

struct SynBucket
{
    static constexpr uint32_t bucket_size = 16;

    OneSynConnection connections[bucket_size];
    std::mutex mutex;
    uint32_t time_overflow;

    SynBucket();
};

enum class SynInsertResult : uint8_t
{
	new_record = 0,
    exists = 1,
	overflow
};

struct SynOperationData
{
    uint32_t bucket_index;
    uint32_t record_index;
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t recv_seq;
};

class ServiceSynConnections
{
public:
    bool Initialize(proxy_service_id_t service_id, uint32_t number_buckets, dataplane::memory_manager* memory_manager);
    SynInsertResult TryInsertClient(uint32_t addr, uint16_t port, uint32_t seq, uint32_t current_time, SynOperationData& operation_data);
    void UpdateLocal(uint32_t addr, uint16_t port, uint32_t current_time, const SynOperationData& operation_data);   // todo - error result
    void Remove(uint32_t addr, uint16_t port, uint32_t current_time, const SynOperationData& operation_data);   // todo - error result
    bool SearchAndRemove(uint32_t addr, uint16_t port, uint32_t current_time, SynOperationData& operation_data);
    bool UpdateTimeFromServerAnswer(uint32_t addr, uint16_t port, uint32_t current_time);
    void GetSyn(proxy_service_id_t service_id, uint32_t current_time, common::idp::proxy_syn::response& response);

private:
    SynBucket* buckets_ = nullptr;
    uint32_t number_buckets_ = 0;
    bool initialized_ = false;
};

}
