#pragma once

#include <optional>
#include <stdio.h>
#include <string>
#include <variant>

#include "common/ringlog.h"
#include "common/type.h"
#include "helper.h"

namespace ringlog
{

void ChangeState(bool enabled, uint32_t value)
{
    interface::dataPlane dataplane;
	common::idp::updateGlobalBase::request globalbase;
    common::idp::updateGlobalBase::ringlog_state_update::request request(enabled, value);
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::ringlog_state_update, request);
	dataplane.updateGlobalBase(globalbase);
}

void enable(std::optional<std::string> value)
{
    if (!value.has_value())
    {
        ChangeState(true, 0);
    }
    else if (value->find('.') == std::string::npos)
    {
        ChangeState(true, std::stoi(*value));
    }
    else
    {
        ChangeState(true, rte_cpu_to_be_32(common::ipv4_address_t(*value)));
    }
}

void disable()
{
    ChangeState(false, 0);
}

void print()
{
    common::sdp::DataPlaneInSharedMemory sdp_data;
	OpenSharedMemoryDataplaneBuffers(sdp_data, true);

	for (const auto& [coreId, worker_info] : sdp_data.workers)
	{
		auto* buffer = common::sdp::ShiftBuffer<common::ringlog::LogRecord*>(worker_info.buffer,
		                                                   sdp_data.metadata_worker.start_ring_log);
		
        for (uint32_t index = 0; index < RINGLOG_SIZE_PER_WORKER; index++)
        {
            uint64_t time = buffer[index].time;
            if (time != 0)
            {
                uint64_t value = buffer[index].data;
                uint8_t event = value & 0xff;
                uint16_t value1 = rte_be_to_cpu_16((value >> 8) & 0xffff);
                uint16_t value2 = rte_be_to_cpu_16((value >> 24) & 0xffff);
                printf("%.3f %3d %c%02u %5u %5u\n", time * 0.001, coreId, (event >= 200 ? 'E' : ' '), event % 200, value1, value2);
            }
        }
	}
}

}

namespace workerstat
{

void ChangeState(bool enabled)
{
    interface::dataPlane dataplane;
	common::idp::updateGlobalBase::request globalbase;
    common::idp::updateGlobalBase::worker_handler_stat_update::request request(enabled);
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::worker_handler_stat_update, request);
	dataplane.updateGlobalBase(globalbase);
}

void enable()
{
    ChangeState(true);
}

void disable()
{
    ChangeState(false);
}

struct OneCoreStat
{
    uint64_t count = 0;
    uint64_t min = WORKER_HANDLER_STAT_SIZE;
    uint64_t max = 0;
    uint64_t sum = 0;

    void Add(uint32_t* counters_cur, uint32_t* counters_prev)
    {
        for (uint64_t index = 0; index < WORKER_HANDLER_STAT_SIZE; index++)
        {
            uint32_t count_cur = counters_cur[index] - counters_prev[index];
            count += count_cur;
            sum += count_cur * index;
            if (count_cur != 0)
            {
                if (index < min)
                {
                    min = index;
                }
                if (index > max)
                {
                    max = index;
                }
            }
        }
    }

    void Add(const OneCoreStat& other)
    {
        count += other.count;
        sum += other.sum;
        min = std::min(min, other.min);
        max = std::max(max, other.max);
    }

    std::string ToString()
    {
        if (count == 0)
        {
            return std::string{};
        }

        char buffer[128];
        snprintf(buffer, sizeof(buffer), "%2ld [%2ld:%2ld] %ld", sum / count, min, max, count);
        return std::string(buffer);
    }
};

#define TIME_INTERVAL1 5
#define TIME_INTERVAL2 20

struct OneCoreInfo
{
    tCoreId coreId;
    uint32_t* stat_shmem;
    std::vector<std::vector<uint32_t>> stat32;
    std::vector<OneCoreStat> time_stat;

    void CopyStat32(uint32_t index)
    {
        memcpy(stat32[index].data(), stat_shmem, WORKER_HANDLER_STAT_SIZE * sizeof(uint32_t));
    }

    OneCoreStat BuildStat(uint32_t start, uint32_t count)
    {
        OneCoreStat result;
        for (uint32_t index = 0; index < count; index++)
        {
            result.Add(time_stat[start]);
            start = (start == 0 ? TIME_INTERVAL2 - 1 : start - 1);
        }
        return result;
    }
};

void print()
{
	common::sdp::DataPlaneInSharedMemory sdp_data;
	OpenSharedMemoryDataplaneBuffers(sdp_data, true);

	uint32_t cores_count = sdp_data.workers.size();
	std::vector<OneCoreInfo> cores_info(cores_count);
	uint32_t index_core = 0;
	for (const auto& [coreId, worker_info] : sdp_data.workers)
	{
        OneCoreInfo& info = cores_info[index_core++];
		info.coreId = coreId;
		info.stat_shmem =
		        common::sdp::ShiftBuffer<uint32_t*>(worker_info.buffer,
		                                            sdp_data.metadata_worker.start_workers_stats);
		info.stat32.resize(2);
		info.stat32[0].resize(WORKER_HANDLER_STAT_SIZE);
		info.stat32[1].resize(WORKER_HANDLER_STAT_SIZE);
		info.CopyStat32(0);

		info.time_stat.resize(TIME_INTERVAL2);
	}
    uint32_t index_work = 0;
    uint32_t index_time = 0;
    uint32_t index_ms = 0;

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
        for (uint32_t index_core = 0; index_core < cores_count; index_core++)
        {
            OneCoreInfo& info = cores_info[index_core];
            info.CopyStat32(1 - index_work);
            info.time_stat[index_time].Add(info.stat32[1 - index_work].data(), info.stat32[index_work].data());
        }
        index_work = 1 - index_work;
        index_ms++;

        if (index_ms != 1000)
        {
            continue;
        }

        // print table
        TablePrinter table;
        table.insert_row("core", "1 sec", std::to_string(TIME_INTERVAL1) + " sec", std::to_string(TIME_INTERVAL2) + " sec");
        for (uint32_t index_core = 0; index_core < cores_count; index_core++)
        {
            OneCoreInfo& info = cores_info[index_core];
            std::string str1 = info.time_stat[index_time].ToString();
            std::string str2 = info.BuildStat(index_time, TIME_INTERVAL1).ToString();
            std::string str3 = info.BuildStat(index_time, TIME_INTERVAL2).ToString();
            table.insert_row(info.coreId, str1, str2, str3);
        }
        table.Render();

        // change indexes and clear stat for current second
        index_ms = 0;
        index_time = (index_time + 1) % TIME_INTERVAL2;
        for (uint32_t index_core = 0; index_core < cores_count; index_core++)
        {
            cores_info[index_core].time_stat[index_time] = OneCoreStat();
        }
    }
}

}
