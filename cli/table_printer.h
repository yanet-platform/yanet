#pragma once

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#include "common/utils.h"
#include "converter.h"

class TablePrinter
{
public:
	TablePrinter(const converter::config_t config = {}) :
	        config_(config) {}

	// Insert arbitrary number of values as one row
	template<typename... Args>
	void insert_row(Args&&... args)
	{
		insert_row({converter::to_string(std::forward<Args>(args), config_)...});
	}

	// Insert tuple as one row
	template<typename... Args>
	void insert_row(const std::tuple<Args...>& tuple)
	{
		std::vector<std::string> row;

		std::apply([&row, this](const Args&... args) {
			(row.push_back(converter::to_string(args, config_)), ...);
		},
		           tuple);

		insert_row(std::move(row));
	}

	// Insert pair as one row
	template<typename First, typename Second>
	void insert_row(const std::pair<First, Second>& pair)
	{
		std::vector<std::string> row;
		row.push_back(converter::to_string(pair.first, config_));
		row.push_back(converter::to_string(pair.second, config_));

		insert_row(std::move(row));
	}

	// Insert values from a container as one row
	template<typename Iterator, typename = typename std::iterator_traits<Iterator>::iterator_category>
	void insert_row(Iterator begin, Iterator end)
	{
		std::vector<std::string> row;
		for (auto it = begin; it != end; ++it)
		{
			row.push_back(converter::to_string(*it, config_));
		}
		insert_row(std::move(row));
	}

	/**
	 * Insert values from a container as many rows
	 *
	 * Useful when we have a container of containers like the "response"
	 * object obtained from controlplane
	 */
	template<typename Iterator, typename = typename std::iterator_traits<Iterator>::iterator_category>
	void insert(Iterator begin, Iterator end)
	{
		for (auto it = begin; it != end; ++it)
		{
			insert_row(*it);
		}
	}

	void Print()
	{
		std::string format;
		if (const char* format_pointer = std::getenv("YANET_FORMAT"))
		{
			format = format_pointer;
		}

		(format == "json") ? print_json() : print_default();
	}

	void Render()
	{
		std::cout << "\033[H\033[2J" << std::flush;

		print_default();
		table_.clear();
	}

private:
	void insert_row(std::vector<std::string>&& row)
	{
		if (row.size() > column_lengths_.size())
		{
			column_lengths_.resize(row.size(), 0);
		}

		for (uint32_t i = 0; i < row.size(); ++i)
		{
			if (column_lengths_[i] < row[i].size())
			{
				column_lengths_[i] = row[i].size();
			}
		}

		table_.push_back(std::move(row));
	}

	void print_default()
	{
		if (table_.empty() || column_lengths_.empty())
		{
			return;
		}

		std::vector<std::string> user_selected_col_names;
		if (const char* columns_pointer = std::getenv("YANET_FORMAT_COLUMNS"))
		{
			user_selected_col_names = utils::split(columns_pointer, ',');
		}

		bool print_selected_cols_only = !user_selected_col_names.empty();

		// The header row contains the table's column names
		const auto& header_row = table_.front();

		/*
		 * If the user has specified certain columns to be printed in a specific order,
		 * we need to map each column's index from the user-provided list to its corresponding
		 * index in the table.
		 * If no specific column selection or order is provided by the user,
		 * print all columns in the default table order:
		 */
		std::unordered_map<std::string, size_t> header_indices;
		for (size_t idx = 0; idx < header_row.size(); ++idx)
		{
			header_indices[header_row[idx]] = idx;
		}

		std::vector<size_t> columns_order;
		if (print_selected_cols_only)
		{
			for (const auto& col_name : user_selected_col_names)
			{
				auto it = header_indices.find(col_name);
				if (it != header_indices.end())
				{
					columns_order.push_back(it->second);
				}
				else
				{
					std::cerr << "The column name '" << col_name
					          << "' in YANET_FORMAT_COLUMNS does not match any "
					          << "available column name. Skipping it." << std::endl;
					std::cerr << "Available column names are: ";
					for (auto it = header_row.begin(); it != header_row.end(); ++it)
					{
						std::cerr << *it;
						if (std::next(it) != header_row.end())
						{
							std::cerr << ", ";
						}
					}
					std::cerr << std::endl;
				}
			}
		}
		else
		{
			columns_order.resize(header_row.size());
			std::iota(columns_order.begin(), columns_order.end(), 0);
		}

		if (columns_order.empty())
		{
			return;
		}

		print_row(header_row, columns_order, true);

		for (size_t row_idx = 1; row_idx < table_.size(); ++row_idx)
		{
			const auto& row = table_[row_idx];
			print_row(row, columns_order, false);
		}
	}

	void print_json()
	{
		if (table_.empty())
		{
			return;
		}

		std::vector<std::string> format_keys;
		if (const char* format_keys_pointer = std::getenv("YANET_FORMAT_KEYS"))
		{
			format_keys = utils::split(format_keys_pointer, ',');
		}

		// The header row contains the table's column names
		const auto& header_row = table_.front();

		// Build a mapping from column indices to format_keys indices
		std::unordered_map<size_t, size_t> format_keys_i;
		if (!format_keys.empty())
		{
			for (size_t idx = 0; idx < header_row.size(); ++idx)
			{
				auto it = std::find(format_keys.begin(), format_keys.end(), header_row[idx]);
				if (it != format_keys.end())
				{
					size_t format_idx = std::distance(format_keys.begin(), it);
					format_keys_i[idx] = format_idx;
				}
			}
		}

		nlohmann::json json_root;

		// Process each data row
		for (size_t row_idx = 1; row_idx < table_.size(); ++row_idx)
		{
			const auto& row = table_[row_idx];

			std::vector<std::string> tree(format_keys.size());

			nlohmann::json json_row;
			for (size_t idx = 0; idx < row.size(); ++idx)
			{
				auto it = format_keys_i.find(idx);
				if (it != format_keys_i.end())
				{
					// This column is part of the nested keys
					size_t tree_idx = it->second;
					tree[tree_idx] = row[idx];
				}
				else if (idx < header_row.size())
				{
					// Regular key-value pair in the row
					json_row[header_row[idx]] = row[idx];
				}
			}

			nlohmann::json* json_current = &json_root;
			for (const auto& key : tree)
			{
				json_current = &((*json_current)[key]);
			}

			json_current->push_back(json_row);
		}

		std::cout << json_root.dump(2) << std::endl;
	}

	void print_row(const std::vector<std::string>& row,
	               const std::vector<size_t>& columns_order,
	               bool is_header)
	{
		for (size_t i = 0; i < columns_order.size(); ++i)
		{
			size_t col_idx = columns_order[i];
			auto col_width = static_cast<int>(column_lengths_[col_idx]);
			const auto& cell = row[col_idx];

			if (i == 0)
			{
				std::cout << std::left << std::setw(col_width) << cell;
			}
			else
			{
				std::cout << "  "; // Add separation between columns
				if (i != columns_order.size() - 1)
				{
					// For all but the last column, use setw
					std::cout << std::left << std::setw(col_width) << cell;
				}
				else
				{
					// Do not pad the last column
					std::cout << cell;
				}
			}
		}
		std::cout << '\n';

		if (is_header)
		{
			// Print a separator line after the header
			for (size_t i = 0; i < columns_order.size(); ++i)
			{
				size_t col_idx = columns_order[i];
				auto col_width = column_lengths_[col_idx];

				if (i == 0)
				{
					std::cout << std::string(col_width, '-');
				}
				else
				{
					std::cout << "  " << std::string(col_width, '-');
				}
			}
			std::cout << '\n';
		}
	}

	converter::config_t config_;
	std::vector<std::vector<std::string>> table_;
	std::vector<size_t> column_lengths_;
};
