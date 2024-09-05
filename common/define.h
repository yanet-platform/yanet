#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <optional>
#include <set>
#include <vector>

/**
 *  GCC 7.5 version which we have to support for now due to Ubuntu 18 have a bug
 *  (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81767) where unused variables
 *  in structured bindings are incorrectly flagged as warnings, even though
 *  they "can't" be used, cause they are not a real variables.
 *
 *  Previously, code used `(void)var;` to suppress these warnings, but this
 *  approach was ugly and harder to grep.
 *
 *  One should use this macro in structured bindings to mark unused bunding.
 *
 *  Once we move to a newer GCC version where this bug is fixed,
 *  we can easily remove this macro as it is much easier to grep and remove
 *  than those void(var) statements.
 */
#define GCC_BUG_UNUSED(arg) (void)(arg)

#define YANET_LOG_PRINT(msg, args...) fprintf(stdout, msg, ##args)

namespace common::log
{
enum LogPriority
{
	TLOG_EMERG = 0 /* "EMERG" */,
	TLOG_ALERT = 1 /* "ALERT" */,
	TLOG_CRIT = 2 /* "CRITICAL_INFO" */,
	TLOG_ERR = 3 /* "ERROR" */,
	TLOG_WARNING = 4 /* "WARNING" */,
	TLOG_NOTICE = 5 /* "NOTICE" */,
	TLOG_INFO = 6 /* "INFO" */,
	TLOG_DEBUG = 7 /* "DEBUG" */,
	TLOG_RESOURCES = 8 /* "RESOURCES" */
};
extern LogPriority logPriority;
} // common::log

#define YANET_LOG_(name, level, msg, args...)                                                                                          \
	do                                                                                                                             \
		if (common::log::logPriority >= common::log::TLOG_##level)                                                             \
		{                                                                                                                      \
			timespec ts;                                                                                                   \
			timespec_get(&ts, TIME_UTC);                                                                                   \
			fprintf(stdout, "[" name "] %lu.%06lu %s:%d: " msg, ts.tv_sec, ts.tv_nsec / 1000, __FILE__, __LINE__, ##args); \
			fflush(stdout);                                                                                                \
		}                                                                                                                      \
	while (0)
#define YANET_LOG(level, msg, args...) YANET_LOG_(#level, level, msg, ##args)

#define YANET_LOG_DEBUG(msg, args...) YANET_LOG(DEBUG, msg, ##args)
#define YANET_LOG_INFO(msg, args...) YANET_LOG(INFO, msg, ##args)
#define YANET_LOG_NOTICE(msg, args...) YANET_LOG(NOTICE, msg, ##args)
#define YANET_LOG_WARNING(msg, args...) YANET_LOG(WARNING, msg, ##args)
#define YANET_LOG_ERROR(msg, args...) YANET_LOG_("ERROR", ERR, msg, ##args)

#define YANET_ALWAYS_INLINE __attribute__((always_inline))
#define YANET_NEVER_INLINE __attribute__((noinline))

#define YANET_MEMORY_BARRIER_COMPILE __asm__ __volatile__("" :: \
	                                                          : "memory")

#define YANET_ACL_ID_UNKNOWN ((tAclId)(0))

#define YANET_NETWORK_TYPE_UNKNOWN ((uint16_t)(0))
#define YANET_TRANSPORT_TYPE_UNKNOWN ((uint8_t)(254))

#define TCP_CWR_FLAG (0x80)
#define TCP_ECN_FLAG (0x40)
#define TCP_URG_FLAG (0x20)
#define TCP_ACK_FLAG (0x10)
#define TCP_PSH_FLAG (0x08)
#define TCP_RST_FLAG (0x04)
#define TCP_SYN_FLAG (0x02)
#define TCP_FIN_FLAG (0x01)

#define TCP_OPTION_KIND_EOL (0)
#define TCP_OPTION_KIND_NOP (1)
#define TCP_OPTION_KIND_MSS (2)
#define TCP_OPTION_KIND_WS (3)
#define TCP_OPTION_KIND_SP (4)
#define TCP_OPTION_KIND_SACK (5)
#define TCP_OPTION_KIND_TS (8)

#define YANET_TCP_OPTION_YA_KIND (253)
#define YANET_TCP_OPTION_YA_MAGIC (0x7961)

#define TCP_OPTION_MSS_LEN (4)
#define YANET_BALANCER_DEFAULT_MSS_SIZE 536
#define YANET_BALANCER_FIX_MSS_SIZE 1220
#define YANET_BALANCER_FIX_MSS_FLAG ((uint8_t)(1u << 0))

#define YANET_BALANCER_OPS_FLAG ((uint8_t)(1u << 1))
#define YANET_BALANCER_PURE_L3 ((uint8_t)(1u << 2))
#define YANET_BALANCER_PURE_ROUND_ROBIN ((uint8_t)(1u << 3))

#define CALCULATE_LOGICALPORT_ID(portId, vlanId) ((portId << 13) | ((vlanId & 0xFFF) << 1) | 1)

#if __cpp_exceptions
#define YANET_THROW(message) throw std::runtime_error(std::string(message))
#else // __cpp_exceptions
#define YANET_THROW(message)                                               \
	do                                                                 \
	{                                                                  \
		YANET_LOG_ERROR("%s\n", std::string_view(message).data()); \
		std::abort();                                              \
	} while (0)
#endif // __cpp_exceptions

#define YANET_RIB_PRIORITY_DEFAULT ((uint32_t)10000)
#define YANET_RIB_PRIORITY_ROUTE_TUNNEL_FALLBACK ((uint32_t)11000)
#define YANET_RIB_PRIORITY_ROUTE_REPEAT ((uint32_t)12000)
#define YANET_RIB_VRF_DEFAULT "default"
#define YANET_RIB_VRF_MAX_NUMBER 64

#define YANET_DEFAULT_BGP_AS ((uint32_t)13238)
#define YANET_DEFAULT_ROUTE_TUNNEL_LABEL ((uint32_t)3199)
#define YANET_DEFAULT_ROUTE_TUNNEL_PATH_INFORMATION "127.0.0.1:10000"

#define YANET_NETWORK_FLAG_FRAGMENT ((uint8_t)(1u << 0))
#define YANET_NETWORK_FLAG_NOT_FIRST_FRAGMENT ((uint8_t)(1u << 1))
#define YANET_NETWORK_FLAG_HAS_EXTENSION ((uint8_t)(1u << 2))

#define YANET_NEXTHOP_FLAG_DIRECTLY ((uint16_t)(1u << 0))

/*
 * @brief Macro to define serialization-friendly tuple accessors.
 *
 * Example usage:
 * \code
 * class MyClass {
 * public:
 *     int a;
 *     std::string b;
 *
 *     // Automatically defines as_tuple() methods
 *     SERIALIZABLE(a, b);
 * };
 * \endcode
 *
 * In cases where serialization/deserialization logic for a class is not
 * straightforward or requires custom handling, you should define explicit
 * `pop` and `push` methods as before, instead of using this macro.
 *
 * @param __VA_ARGS__ List of member variables to include in the tuple.
 */
#define SERIALIZABLE(...)                                 \
	auto as_tuple() { return std::tie(__VA_ARGS__); } \
	auto as_tuple() const { return std::tie(__VA_ARGS__); }

/// @todo: move
template<typename map_T,
         typename key_T>
inline bool exist(const map_T& map, const key_T& key)
{
	return map.find(key) != map.end();
}

template<typename key_T,
         typename value_T>
inline bool exist(const std::map<key_T, value_T>& map, const key_T& key)
{
	return map.find(key) != map.end();
}

template<typename key_T>
inline bool exist(const std::set<key_T>& set, const key_T& key)
{
	return set.find(key) != set.end();
}

/// @todo: move
template<typename type_T>
bool check_size(const std::vector<type_T>& vector,
                const std::size_t& size)
{
	return vector.size() * sizeof(type_T) == size;
}

template<typename list_T>
inline void limit_insert(list_T& list,
                         const char* name,
                         const std::optional<uint32_t>& socket_id,
                         const uint64_t& current,
                         const uint64_t& maximum)
{
	list.emplace_back(name, socket_id, current, maximum);
}

template<typename list_T>
inline void limit_insert(list_T& list,
                         const char* name,
                         const std::optional<uint32_t>& socket_id,
                         const std::tuple<uint64_t, uint64_t>& current_maximum)
{
	const auto& [current, maximum] = current_maximum;
	limit_insert(list, name, socket_id, current, maximum);
}

template<typename list_T>
inline void limit_insert(list_T& list,
                         const char* name,
                         const uint64_t& current,
                         const uint64_t& maximum)
{
	list.emplace_back(name, std::nullopt, current, maximum);
}

template<typename list_T>
inline void limit_insert(list_T& list,
                         const char* name,
                         const std::tuple<uint64_t, uint64_t>& current_maximum)
{
	const auto& [current, maximum] = current_maximum;
	limit_insert(list, name, std::nullopt, current, maximum);
}
