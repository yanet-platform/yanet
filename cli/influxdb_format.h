#pragma once

#include <iostream>
#include <map>
#include <optional>
#include <vector>

#include "converter.h"

namespace influxdb_format
{

static void replace_all(std::string& string,
                        const std::string& search,
                        const std::string& replace)
{
	for (auto pos = string.find(search);
	     pos != std::string::npos;
	     pos = string.find(search, pos + replace.length()))
	{
		string.replace(pos, search.length(), replace);
	}
}

template<typename value_T>
std::string to_string(const char* key, const std::map<std::string, value_T>& map, const char* suffix, const converter::config_t& config);
template<typename value_T>
std::string to_string(const char* key, const std::optional<value_T>& value, const char* suffix, const converter::config_t& config);
template<typename value_T>
std::string to_string(const char* key, const value_T& value, const char* suffix, const converter::config_t& config);

template<typename value_T>
std::string to_string(const char* key,
                      const std::map<std::string, value_T>& map,
                      const char* suffix,
                      const converter::config_t& config)
{
	bool first = true;
	std::ostringstream result;
	for (const auto& [name, value] : map)
	{
		if (!first)
		{
			result << ",";
		}

		std::string map_key = key;
		map_key += name;

		result << influxdb_format::to_string(map_key.data(), value, suffix, config);
		first = false;
	}

	return result.str();
}

template<typename value_T>
std::string to_string(const char* key,
                      const std::optional<value_T>& value,
                      const char* suffix,
                      const converter::config_t& config)
{
	std::string result;

	if (value)
	{
		result = influxdb_format::to_string(key, *value, suffix, config);
	}

	return result;
}

template<typename value_T>
std::string to_string(const char* key,
                      const value_T& value,
                      const char* suffix,
                      const converter::config_t& config)
{
	std::string result;
	result += key;
	result += "=";
	result += converter::to_string(value, config);
	result += suffix;
	replace_all(result, " ", "\\ ");
	return result;
}

class base_t
{
public:
	virtual ~base_t()
	{
	}

	const std::string& to_string() const
	{
		return string;
	}

protected:
	std::string string;
};

class key_t : public base_t
{
public:
	template<typename value_T>
	key_t(const char* key,
	      const value_T& value,
	      const converter::config_t config = {})
	{
		string = influxdb_format::to_string(key, value, "", config);
	}
};

class value_t : public base_t
{
public:
	template<typename value_T>
	value_t(const char* key,
	        const value_T& value,
	        const char* suffix = "u",
	        const converter::config_t config = {})
	{
		string = influxdb_format::to_string(key, value, suffix, config);
	}
};

void print(const char* name,
           const std::vector<key_t>& keys,
           const std::vector<value_t>& values)
{
	std::ostringstream line;
	line << name;

	for (const auto& key : keys)
	{
		if (key.to_string().size())
		{
			line << "," << key.to_string();
		}
	}

	if (values.size())
	{
		bool first = true;
		for (const auto& value : values)
		{
			if (value.to_string().size())
			{
				if (first)
				{
					line << " ";
				}
				else
				{
					line << ",";
				}

				line << value.to_string();
				first = false;
			}
		}
	}

	std::cout << line.str() << std::endl;
}

void print(const std::string& name,
           const std::vector<key_t>& keys,
           const std::vector<value_t>& values)
{
	print(name.data(), keys, values);
}

template<typename array_T,
         typename index_T>
void print_histogram(const char* name,
                     const std::vector<key_t>& keys,
                     const char* tag_name,
                     const char* value_name,
                     const array_T& array,
                     const index_T start,
                     const index_T end)
{
	for (unsigned int i = (unsigned int)start;
	     i <= (unsigned int)end;
	     i++)
	{
		std::ostringstream line;
		line << name;

		for (const auto& key : keys)
		{
			if (key.to_string().size())
			{
				line << "," << key.to_string();
			}
		}

		line << "," << influxdb_format::to_string(tag_name, i - (unsigned int)start + 1, "", {});
		line << " " << influxdb_format::to_string(value_name, array[i], "u", {});

		std::cout << line.str() << std::endl;
	}
}

}
