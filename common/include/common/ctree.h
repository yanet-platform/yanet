#pragma once

#include <functional>

#include "define.h"
#include "stream.h"

namespace common
{

template<std::size_t values_size_T,
         typename... counters_T>
struct ctree
{
	using values_t = std::array<uint64_t, values_size_T>;

	ctree()
	{
		if constexpr (sizeof...(counters_T) > 0)
		{
			root_node = new node_t<counters_T...>();
		}
		else
		{
			root_node = new node_base_t();
		}
	}
	ctree(ctree&& other)
	{
		if (this != &other)
		{
			*this = std::move(other);
		}
	}
	ctree& operator=(ctree&& other)
	{
		std::swap(root_node, other.root_node);
		return *this;
	}

	~ctree()
	{
		delete root_node;
	}

	/// @todo: delete copy

	void append(const counters_T&... counters,
	            const values_t& values)
	{
		if constexpr (sizeof...(counters_T) > 0)
		{
			static_cast<node_t<counters_T...>*>(root_node)->append(counters..., values);
		}
		else
		{
			root_node->append(values);
		}
	}

	void apply(const counters_T&... counters,
	           const std::function<void(const std::tuple<std::optional<counters_T>...>, values_t&)>& callback)
	{
		std::tuple<std::optional<counters_T>...> keys;

		if constexpr (sizeof...(counters_T) > 0)
		{
			static_cast<node_t<counters_T...>*>(root_node)->apply(counters..., callback, keys);
		}
		else
		{
			root_node->apply(callback, keys);
		}
	}

	void clear()
	{
		delete root_node;

		if constexpr (sizeof...(counters_T) > 0)
		{
			root_node = new node_t<counters_T...>();
		}
		else
		{
			root_node = new node_base_t();
		}
	}

	void convert_update(const std::map<counters_T, std::string>&... convert) const
	{
		if constexpr (sizeof...(counters_T) > 0)
		{
			static_cast<node_t<counters_T...>*>(root_node)->convert_update(convert...);
		}
	}

	void print(const std::vector<std::string>& key_names,
	           const std::function<void(const std::string& key, const values_t&)>& callback) const
	{
		root_node->print("", 0, key_names, callback);
	}

	void pop(stream_in_t& stream)
	{
		root_node->pop(stream);
	}

	void push(stream_out_t& stream) const
	{
		root_node->push(stream);
	}

	void merge(const ctree<values_size_T, counters_T...>& other)
	{
		root_node->merge(other.root_node);
	}

	struct node_base_t
	{
		node_base_t() = default;
		node_base_t(const node_base_t& other) :
		        values{other.values} {}
		node_base_t(const values_t& values) :
		        values{values} {}
		virtual ~node_base_t() = default;

		void append(const values_t& values)
		{
			auto& a = this->values;
			auto& b = values;
			for (std::size_t i = 0, e = a.size(); i < e; ++i)
			{
				a[i] += b[i];
			}
		}

		void apply(const std::function<void(const std::tuple<std::optional<counters_T>...>, values_t&)>& callback,
		           std::tuple<std::optional<counters_T>...>& keys)
		{
			callback(keys, this->values);
		}

		virtual void print(const std::string& key,
		                   const uint32_t& key_index,
		                   const std::vector<std::string>& key_names,
		                   const std::function<void(const std::string& key, const values_t&)>& callback) const
		{
			GCC_BUG_UNUSED(key_index);
			GCC_BUG_UNUSED(key_names);

			callback(key, values);
		}

		virtual void pop(stream_in_t& stream)
		{
			stream.pop(values);
		}

		virtual void push(stream_out_t& stream) const
		{
			stream.push(values);
		}

		virtual void merge(const node_base_t* other)
		{
			this->append(other->values);
		}

		values_t values;
	};

	template<typename next_counter_T,
	         typename... next_counters_T>
	struct node_t : public node_base_t
	{
		node_t() = default;
		node_t(const node_t& other) :
		        node_base_t{other}, convert{other.convert}
		{
			for (const auto& [key, value] : other.next)
			{
				if constexpr (sizeof...(next_counters_T) != 0)
				{
					using child_t = node_t<next_counters_T...>;
					next.emplace(key, new child_t{*static_cast<child_t*>(value)});
				}
				else
				{
					next.emplace(key, new node_base_t{*value});
				}
			}
		}
		~node_t() override
		{
			for (auto& [next_counter, next_node] : next)
			{
				GCC_BUG_UNUSED(next_counter);
				delete next_node;
			}
		}

		using node_base_t::append;
		using node_base_t::apply;

		void append(const next_counter_T& next_counter,
		            const next_counters_T&... next_counters,
		            const values_t& values)
		{
			node_base_t::append(values);

			if (!exist(next, next_counter))
			{
				if constexpr (sizeof...(next_counters_T) > 0)
				{
					next[next_counter] = new node_t<next_counters_T...>();
				}
				else
				{
					next[next_counter] = new node_base_t();
				}
			}

			if constexpr (sizeof...(next_counters_T) > 0)
			{
				static_cast<node_t<next_counters_T...>*>(next[next_counter])->append(next_counters..., values);
			}
			else
			{
				next[next_counter]->append(values);
			}
		}

		void apply(const next_counter_T& next_counter,
		           const next_counters_T&... next_counters,
		           const std::function<void(const std::tuple<std::optional<counters_T>...>, values_t&)>& callback,
		           std::tuple<std::optional<counters_T>...>& keys)
		{
			node_base_t::apply(callback, keys);

			if (!exist(next, next_counter))
			{
				if constexpr (sizeof...(next_counters_T) > 0)
				{
					next[next_counter] = new node_t<next_counters_T...>();
				}
				else
				{
					next[next_counter] = new node_base_t();
				}
			}

			std::get<sizeof...(counters_T) - sizeof...(next_counters_T) - 1>(keys) = next_counter;

			if constexpr (sizeof...(next_counters_T) > 0)
			{
				static_cast<node_t<next_counters_T...>*>(next[next_counter])->apply(next_counters..., callback, keys);
			}
			else
			{
				next[next_counter]->apply(callback, keys);
			}
		}

		void convert_update(const std::map<next_counter_T, std::string>& next_convert,
		                    const std::map<next_counters_T, std::string>&... next_converts) const
		{
			this->convert = next_convert;

			if constexpr (sizeof...(next_counters_T) > 0)
			{
				for (const auto& [next_counter, next_node] : next)
				{
					GCC_BUG_UNUSED(next_counter);
					static_cast<node_t<next_counters_T...>*>(next_node)->convert_update(next_converts...);
				}
			}
		}

		void print(const std::string& key,
		           const uint32_t& key_index,
		           const std::vector<std::string>& key_names,
		           const std::function<void(const std::string& key, const values_t&)>& callback) const override
		{
			node_base_t::print(key, key_index, key_names, callback);

			for (const auto& [next_counter, next_node] : next)
			{
				std::string next_counter_string;
				if (exist(convert, next_counter))
				{
					next_counter_string = convert[next_counter];
				}
				else
				{
					if constexpr (std::is_constructible_v<std::string, decltype(next_counter)>)
					{
						next_counter_string = std::string(next_counter);
					}
					else
					{
						next_counter_string = std::to_string(next_counter);
					}
				}

				next_node->print(key + "," + key_names[key_index] + "=" + next_counter_string,
				                 key_index + 1,
				                 key_names,
				                 callback);
			}
		}

		void pop(stream_in_t& stream) override
		{
			node_base_t::pop(stream);

			std::size_t count = 0;

			stream.pop(count);

			for (std::size_t i = 0; i < count; i++)
			{
				next_counter_T key;
				stream.pop(key);

				if constexpr (sizeof...(next_counters_T) > 0)
				{
					next[key] = new node_t<next_counters_T...>();
				}
				else
				{
					next[key] = new node_base_t();
				}

				next[key]->pop(stream);
			}
		}

		void push(stream_out_t& stream) const override
		{
			node_base_t::push(stream);

			std::size_t size = next.size();

			stream.push(size);

			for (const auto& [next_counter, next_node] : next)
			{
				stream.push(next_counter);
				next_node->push(stream);
			}
		}

		void merge(const node_base_t* other) override
		{
			for (const auto& [key, node] : static_cast<const node_t*>(other)->next)
			{
				if (auto it = next.find(key); it != next.end())
				{
					it->second->merge(node);
				}
				else
				{
					if constexpr (sizeof...(next_counters_T) != 0)
					{
						using child_t = node_t<next_counters_T...>;
						next.emplace(key, new child_t(*static_cast<child_t*>(node)));
					}
					else
					{
						next.emplace(key, new node_base_t(*node));
					}
				}
			}

			for (const auto& [key, value] : static_cast<const node_t*>(other)->convert)
			{
				if (convert.find(key) == convert.end())
				{
					convert.emplace(key, value);
				}
			}
		}

		std::map<next_counter_T,
		         node_base_t*>
		        next;

		mutable std::map<next_counter_T,
		                 std::string>
		        convert;
	};

	node_base_t* root_node{};
};

} // namespace common
