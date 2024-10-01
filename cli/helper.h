#pragma once

#include <cstdio>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include "common/sdpclient.h"
#include "common/traits.h"
#include "table_printer.h"

#if __cpp_lib_charconv >= 201606L && !defined(__GNUC__) || __GNUC__ >= 8
#define USE_FROM_CHARS
#endif

#if defined(USE_FROM_CHARS)
#include <charconv>
#else
#include <sstream>
#endif

template<typename T>
static void fill(T& value, const std::string& str)
{
	if constexpr (std::is_same_v<T, bool>)
	{
		if (str == "true")
			value = true;
		else if (str == "false")
			value = false;
		else
			throw std::invalid_argument("Invalid boolean value");
	}
	else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>)
	{
#ifdef USE_FROM_CHARS
		auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
		if (ec != std::errc{})
			throw std::invalid_argument("Invalid numeric value: '" + str + "'");
#else
		std::istringstream iss(str);
		if (!(iss >> value) || !iss.eof())
			throw std::invalid_argument("Invalid numeric value: '" + str + "'");
#endif
	}
	else if constexpr (traits::is_optional_v<T>)
	{
		if (str == "any" || str.empty())
		{
			value.reset();
		}
		else
		{
			typename T::value_type temp;
			fill(temp, str);
			value = std::move(temp);
		}
	}
	else
	{
		value = str;
	}
}

// Fill a tuple with values from a vector of strings
template<typename Tuple, std::size_t... Is>
static void fillTupleImpl(Tuple& tuple, const std::vector<std::string>& args, std::index_sequence<Is...>)
{
	(..., fill(std::get<Is>(tuple), Is < args.size() ? args[Is] : std::string{}));
}

template<typename... Args>
static void fillTuple(std::tuple<Args...>& tuple, const std::vector<std::string>& args)
{
	fillTupleImpl(tuple, args, std::index_sequence_for<Args...>{});
}

// Call function using string arguments
template<typename F>
inline void Call(F&& func, const std::vector<std::string>& string_args)
{
	using ArgsTuple = typename traits::function<F>::args;
	constexpr auto arity = std::tuple_size_v<ArgsTuple>;

	if (string_args.size() > arity)
	{
		throw std::invalid_argument("Invalid arguments count: '" + std::to_string(string_args.size()) +
		                            "', expected at most: '" + std::to_string(arity) + "'");
	}

	utils::decay_tuple<ArgsTuple> args_tuple;
	fillTuple(args_tuple, string_args);
	std::apply(std::forward<F>(func), args_tuple);
}

inline void OpenSharedMemoryDataplaneBuffers(common::sdp::DataPlaneInSharedMemory& sdp_data, bool open_workers_data)
{
	if (common::sdp::SdpClient::ReadSharedMemoryData(sdp_data, open_workers_data) != eResult::success)
	{
		YANET_LOG_ERROR("Error openning shared memory dataplane buffers\n");
		std::exit(1);
	}
}

template<typename Container>
inline void FillAndPrintTable(const std::initializer_list<std::string_view>& headers, const Container& data, const converter::config_t config = {})
{
	TablePrinter table(config);

	table.insert_row(headers.begin(), headers.end());
	table.insert(data.begin(), data.end());
	table.Print();
}
