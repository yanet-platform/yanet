#pragma once

#include <cstdint>

#include "common/type.h"

#define RINGLOG_ENABLED 1

#define RINGLOG_SIZE_PER_WORKER 1024 * 256
static_assert((RINGLOG_SIZE_PER_WORKER & (RINGLOG_SIZE_PER_WORKER - 1)) == 0, "size is not power 2");
#define RINGLOG_SIZE_PER_WORKER_MASK (RINGLOG_SIZE_PER_WORKER - 1)

namespace common::ringlog
{

struct LogRecord
{
    uint64_t time;
    uint64_t data;
};

struct LogInfo
{
    uint64_t index = 0;
    LogRecord* records = nullptr;
};

#if RINGLOG_ENABLED == 1

#define RINGLOG_ADD(ringlog, time, data) {if (ringlog_condition__) { ringlog.records[(ringlog.index++) % RINGLOG_SIZE_PER_WORKER_MASK] = {time, data}; } }
#define RINGLOG_CONDITION(condition) bool ringlog_condition__ = condition;

#else

#define RINGLOG_ADD(ringlog, time, data) {}
#define RINGLOG_CONDITION(condition) {}

#endif

}
