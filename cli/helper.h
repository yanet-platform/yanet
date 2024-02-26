#pragma once

#include <array>
#include <cstdio>
#include <map>
#include <sstream>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include <nlohmann/json.hpp>

#include "converter.h"

template<typename type>
static std::string to_percent(const type current, const type maximum)
{
	double percent = 0.0;
	if (maximum)
	{
		percent = (double)current / (double)maximum;
		percent *= (double)100;
	}

	std::stringstream stream;
	stream << std::fixed << std::setprecision(2) << percent;
	return stream.str();
}

std::vector<std::string> split(const char* string,
                               const char delimiter)
{
	std::vector<std::string> result;
	std::stringstream ss(string);

	std::string part;
	while (std::getline(ss, part, delimiter))
	{
		result.emplace_back(part);
	}

	return result;
}

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
void fillValue(TArg& value)
{
	(void)value;
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

template<size_t TIndex,
         size_t TSize,
         typename TDiffTuple,
         typename TTuple>
void getDiffTuple(TDiffTuple& diff,
                  const TTuple& curr,
                  const TTuple& prev)
{
	if constexpr (TIndex < TSize)
	{
		std::get<TIndex>(diff) = std::get<TIndex>(curr) - std::get<TIndex>(prev);
		getDiffTuple<TIndex + 1, TSize>(diff, curr, prev);
	}
}

template<typename TFirst,
         typename... TSecondArgs>
std::map<TFirst, std::array<int64_t, sizeof...(TSecondArgs)>> getDiff(const std::map<TFirst, std::tuple<TSecondArgs...>>& curr,
                                                                      const std::map<TFirst, std::tuple<TSecondArgs...>>& prev)
{
	std::map<TFirst, std::array<int64_t, sizeof...(TSecondArgs)>> result;

	for (const auto& iter : curr)
	{
		if (prev.find(iter.first) != prev.end())
		{
			std::array<int64_t, sizeof...(TSecondArgs)> diff;
			getDiffTuple<0, sizeof...(TSecondArgs)>(diff, iter.second, prev.find(iter.first)->second);
			result[iter.first] = diff;
		}
	}

	return result;
}

class table_t
{
public:
	table_t(const converter::config_t config = {}) :
	        config(config)
	{
	}

	template<typename... args_T>
	void insert(const args_T&... args)
	{
		std::vector<std::string> row = {converter::to_string(args, config)...};

		if (row.size() > columnLengths.size())
		{
			columnLengths.resize(row.size(), 0);
		}

		for (uint32_t string_i = 0;
		     string_i < row.size();
		     string_i++)
		{
			if (columnLengths[string_i] < row[string_i].size())
			{
				columnLengths[string_i] = row[string_i].size();
			}
		}

		table.emplace_back(row);
	}

	void print_json()
	{
		std::vector<std::string> format_keys;
		std::map<unsigned int, unsigned int> format_keys_i;
		if (const char* format_keys_pointer = std::getenv("YANET_FORMAT_KEYS"))
		{
			format_keys = split(format_keys_pointer, ',');
		}

		std::vector<std::string> keys;

		bool header = true;
		nlohmann::json json_root;
		for (auto& row : table)
		{
			if (header)
			{
				for (uint32_t string_i = 0;
				     string_i < row.size();
				     string_i++)
				{
					for (uint32_t format_i = 0;
					     format_i < format_keys.size();
					     format_i++)
					{
						if (row[string_i] == format_keys[format_i])
						{
							format_keys_i[string_i] = format_i;
						}
					}
				}

				keys = row;
				header = false;
				continue;
			}

			std::vector<std::string> tree;
			tree.resize(format_keys.size());

			nlohmann::json json_row;
			for (uint32_t string_i = 0;
			     string_i < row.size();
			     string_i++)
			{
				if (format_keys_i.count(string_i))
				{
					tree[format_keys_i[string_i]] = row[string_i];
				}
				else
				{
					json_row[keys[string_i]] = row[string_i];
				}
			}

			auto* json_current = &json_root;
			for (const auto& key : tree)
			{
				json_current = &((*json_current)[key]);
			}
			(*json_current).emplace_back(json_row);
		}

		printf("%s\n", json_root.dump(2).data());
	}

	void print_default()
	{
		if (table.size() == 0 ||
		    columnLengths.size() == 0)
		{
			return;
		}

		std::vector<std::string> user_selected_col_names;
		bool print_selected_cols_only = false;
		if (const char* columns_pointer = std::getenv("YANET_FORMAT_COLUMNS"))
		{
			user_selected_col_names = split(columns_pointer, ',');
			print_selected_cols_only = true;
		}

		/* header row contains table's column names */
		auto& header_row = table[0];

		/* If the user listed only specific columns of the table to be printed in specific order,
		   need to build a relation between index of column in user-provided order and its index in the table (only if it does exist in the table):
		   This relation: columns_order[col_idx_in_user_selection] = col_idx_in_table

		   Otherwise, when no custom columns' selection and/or order is provided by the user,
		   print all columns of the table in the table's order:
		   columns_order[col_idx_in_table] = col_idx_in_table */
		std::vector<uint32_t> columns_order;
		if (print_selected_cols_only)
		{
			uint32_t col_idx_in_user_selection = 0;
			while (columns_order.size() < user_selected_col_names.size())
			{
				bool selected_col_name_found = false;
				for (uint32_t col_idx_in_table = 0; col_idx_in_table < header_row.size(); ++col_idx_in_table)
				{
					if (user_selected_col_names[col_idx_in_user_selection] == header_row[col_idx_in_table])
					{
						// col_idx_in_user_selection must be equal to columns_order.size() prior to insertion (check?)
						columns_order.push_back(col_idx_in_table);
						selected_col_name_found = true;
						++col_idx_in_user_selection;
						break;
					}
				}

				if (!selected_col_name_found)
				{
					// evidently, user provided such a column name, which does not exist in the table, cannot print it
					// shifting tail of user_selected_col_names to the left by erasing non-existent user-provided column name
					user_selected_col_names.erase(user_selected_col_names.begin() + col_idx_in_user_selection);
				}
			}
		}
		else
		{
			columns_order.resize(header_row.size());
			std::iota(columns_order.begin(), columns_order.end(), 0);
		}

		if (columns_order.size() == 0)
		{
			/* column names provided by user do not match any column names of the table,
			   or the table does not have any columns at all (what?!) */
			return;
		}

		bool header = true;
		for (auto& row : table)
		{
			printf("%-*s",
			       columnLengths[columns_order[0]],
			       row[columns_order[0]].data());

			for (uint32_t string_i = 1;
			     string_i < columns_order.size();
			     string_i++)
			{
				if (string_i != columns_order.size() - 1)
				{
					printf("  %-*s",
					       columnLengths[columns_order[string_i]],
					       row[columns_order[string_i]].data());
				}
				else
				{
					// Do not explode the last column with padding whitespace bytes.
					printf("  %s",
					       row[columns_order[string_i]].data());
				}
			}

			printf("\n");

			if (header)
			{
				printf("%s", std::string(columnLengths[columns_order[0]], '-').data());

				for (uint32_t string_i = 1;
				     string_i < columns_order.size();
				     string_i++)
				{
					printf("  %s", std::string(columnLengths[columns_order[string_i]], '-').data());
				}

				printf("\n");

				header = false;
			}
		}
	}

	void print()
	{
		std::string format;
		if (const char* format_pointer = std::getenv("YANET_FORMAT"))
		{
			format = format_pointer;
		}

		if (format == "json")
		{
			print_json();
		}
		else
		{
			print_default();
		}
	}

	void render()
	{
		printf("\033[H\033[2J");
		fflush(stdout);

		print_default();
		table.clear();
	}

protected:
	converter::config_t config;
	std::vector<std::vector<std::string>> table;
	std::vector<uint32_t> columnLengths;
};
