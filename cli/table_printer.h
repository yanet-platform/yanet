#pragma once

#include <map>
#include <nlohmann/json.hpp>

#include "common/utils.h"
#include "converter.h"

class TablePrinter
{
public:
	TablePrinter(const converter::config_t config = {}) :
	        config(config) {}

	template<typename... Args>
	void insert(const Args&... args)
	{
		std::vector<std::string> row = {converter::to_string(args, config)...};
		insert_row(row);
	}

	template<typename Iterator, typename = typename std::iterator_traits<Iterator>::iterator_category>
	void insert(Iterator begin, Iterator end)
	{
		std::vector<std::string> row;
		for (auto it = begin; it != end; ++it)
		{
			row.push_back(converter::to_string(*it, config));
		}
		insert_row(row);
	}

	void print_json()
	{
		std::vector<std::string> format_keys;
		std::map<unsigned int, unsigned int> format_keys_i;
		if (const char* format_keys_pointer = std::getenv("YANET_FORMAT_KEYS"))
		{
			format_keys = utils::split(format_keys_pointer, ',');
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
			user_selected_col_names = utils::split(columns_pointer, ',');
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

private:
	void insert_row(const std::vector<std::string>& row)
	{
		if (row.size() > columnLengths.size())
		{
			columnLengths.resize(row.size(), 0);
		}

		for (uint32_t string_i = 0; string_i < row.size(); ++string_i)
		{
			if (columnLengths[string_i] < row[string_i].size())
			{
				columnLengths[string_i] = row[string_i].size();
			}
		}

		table.emplace_back(row);
	}

	converter::config_t config;
	std::vector<std::vector<std::string>> table;
	std::vector<uint32_t> columnLengths;
};
