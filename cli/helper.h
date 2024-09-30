#pragma once

#include <cstdio>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include "common/sdpclient.h"
#include "table_printer.h"

void fillValue(std::optional<uint8_t>& value, const std::string& string)
{
	if (string == "any")
	{
		value = std::nullopt;
	}
	else if (string != "")
	{
		value = std::stoull(string, nullptr, 0);
		;
	}
	else
	{
		value = std::nullopt;
	}
}

void fillValue(std::optional<uint16_t>& value, const std::string& string)
{
	if (string == "any")
	{
		value = std::nullopt;
	}
	else if (string != "")
	{
		value = std::stoull(string, nullptr, 0);
		;
	}
	else
	{
		value = std::nullopt;
	}
}

void fillValue(std::optional<uint32_t>& value, const std::string& string)
{
	if (string == "any")
	{
		value = std::nullopt;
	}
	else if (string != "")
	{
		value = std::stoull(string, nullptr, 0);
		;
	}
	else
	{
		value = std::nullopt;
	}
}

template<typename TArg>
void fillValue(std::optional<TArg>& value, const std::string& string)
{
	if (string == "any")
	{
		value = std::nullopt;
	}
	else if (string != "")
	{
		value = string;
	}
	else
	{
		value = std::nullopt;
	}
}

void fillValue(bool& value, const std::string& string)
{
	if (string == "false" || string == "true")
	{
		value = string == "true";
	}
	else
	{
		throw std::string("invalid argument, must be true or false");
	}
}

void fillValue(uint8_t& value, const std::string& string)
{
	value = std::stoull(string, nullptr, 0);
}

void fillValue(uint16_t& value, const std::string& string)
{
	value = std::stoull(string, nullptr, 0);
}

void fillValue(uint32_t& value, const std::string& string)
{
	value = std::stoull(string, nullptr, 0);
}

template<typename TArg>
void fillValue(TArg& value, const std::string& string)
{
	value = string;
}

template<typename TArg>
void fillValue(std::optional<TArg>& value)
{
	value = std::nullopt;
}

template<typename TArg>
void fillValue([[maybe_unused]] TArg& value)
{
	throw std::string("invalid arguments count");
}

template<size_t TIndex,
         size_t TSize,
         typename TTuple>
void fillTuple(TTuple& tuple, const std::vector<std::string>& stringArgs)
{
	if constexpr (TIndex < TSize)
	{
		if (TIndex < stringArgs.size())
		{
			fillValue(std::get<TIndex>(tuple), stringArgs[TIndex]);
		}
		else
		{
			fillValue(std::get<TIndex>(tuple));
		}

		fillTuple<TIndex + 1, TSize>(tuple, stringArgs);
	}
}

template<typename... TArgs>
void call(void (*func)(TArgs... args),
          const std::vector<std::string>& stringArgs)
{
	if (stringArgs.size() > sizeof...(TArgs))
	{
		throw std::string("invalid arguments count: '") + std::to_string(stringArgs.size()) + "', need: '" + std::to_string(sizeof...(TArgs)) + "'";
	}
	std::tuple<std::decay_t<TArgs>...> tuple;
	fillTuple<0, sizeof...(TArgs)>(tuple, stringArgs);
	std::apply(func, tuple);
}

void OpenSharedMemoryDataplaneBuffers(common::sdp::DataPlaneInSharedMemory& sdp_data, bool open_workers_data)
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
