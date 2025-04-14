#pragma once

#include <functional>

#include "type.h"

namespace common
{

template<typename key_T,
         typename value_T>
class btree
{
public:
	btree() :
	        root(nullptr)
	{
	}

	~btree()
	{
		delete root;
	}

public:
	void insert(const key_T& key,
	            const uint32_t& key_bits,
	            const value_T& value)
	{
		if (!root)
		{
			root = new node_t();
		}

		root->insert(key, key_bits, 0, value);
	}

	template<typename prefix_T>
	void insert(const prefix_T& prefix,
	            const value_T& value)
	{
		insert(prefix.address(),
		       prefix.mask(),
		       value);
	}

	void remove(const key_T& key,
	            const uint32_t& key_bits)
	{
		if (!root)
		{
			return;
		}

		root->remove(key, key_bits, 0);
	}

	template<typename prefix_T>
	void remove(const prefix_T& prefix)
	{
		remove(prefix.address(),
		       prefix.mask());
	}

	void clear()
	{
		if (!root)
		{
			return;
		}

		delete root;
		root = nullptr;
	}

	std::optional<value_T> get(const key_T& key,
	                           const uint32_t& key_bits) const
	{
		if (!root)
		{
			return std::nullopt;
		}

		std::optional<value_T> result;
		root->get(key, key_bits, 0, result);
		return result;
	}

	template<typename prefix_T>
	std::optional<value_T> get(const prefix_T& prefix) const
	{
		return get(prefix.address(),
		           prefix.mask());
	}

	std::vector<std::tuple<key_T, uint32_t>> get_all_top() const
	{
		if (!root)
		{
			return {};
		}

		key_T key;
		std::vector<std::tuple<key_T, uint32_t>> result;
		root->get_all_top(key, 0, result);
		return result;
	}

	std::optional<std::tuple<value_T, uint32_t>> lookup(const key_T& key,
	                                                    const uint32_t& key_bits) const
	{
		if (!root)
		{
			return std::nullopt;
		}

		std::optional<std::tuple<value_T, uint32_t>> result;
		root->lookup(key, key_bits, 0, result);
		return result;
	}

	template<typename prefix_T>
	std::optional<std::tuple<value_T, uint32_t>> lookup(const prefix_T& prefix) const
	{
		return lookup(prefix.address(),
		              prefix.mask());
	}

	void lookup_all(const key_T& key,
	                const uint32_t& key_bits,
	                const std::function<void(const value_T&, const uint32_t)>& callback) const
	{
		if (!root)
		{
			return;
		}

		root->lookup_all(key, key_bits, 0, callback);
	}

	void lookup_deep(const key_T& key,
	                 const uint32_t& key_bits,
	                 const std::function<void(const key_T&, const uint32_t, const value_T&)>& callback) const
	{
		if (!root)
		{
			return;
		}

		key_T key_temp = key;
		root->lookup_deep(key_temp, key_bits, 0, callback, std::nullopt);
	}

protected:
	class node_t
	{
	public:
		node_t() :
		        nexts{nullptr, nullptr}
		{
		}

		~node_t()
		{
			delete nexts[0];
			delete nexts[1];
		}

	public:
		void insert(const key_T& key,
		            const uint32_t& key_bits,
		            const uint32_t& key_bits_current,
		            const value_T& value)
		{
			if (key_bits_current == key_bits)
			{
				this->value = value;
			}
			else
			{
				auto*& next = nexts[key.get_bit(key_bits_current)];

				if (!next)
				{
					next = new node_t();
				}

				next->insert(key, key_bits, key_bits_current + 1, value);
			}
		}

		void remove(const key_T& key,
		            const uint32_t& key_bits,
		            const uint32_t& key_bits_current)
		{
			if (key_bits_current == key_bits)
			{
				value.reset();
				return;
			}
			else
			{
				auto*& next = nexts[key.get_bit(key_bits_current)];

				if (!next)
				{
					return;
				}

				next->remove(key, key_bits, key_bits_current + 1);

				if (!(next->value ||
				      next->nexts[0] ||
				      next->nexts[1]))
				{
					delete next;
					next = nullptr;
				}
			}
		}

		void get(const key_T& key,
		         const uint32_t& key_bits,
		         const uint32_t& key_bits_current,
		         std::optional<value_T>& result) const
		{
			if (key_bits_current == key_bits)
			{
				result = value;
			}
			else
			{
				auto* const& next = nexts[key.get_bit(key_bits_current)];

				if (!next)
				{
					return;
				}

				next->get(key, key_bits, key_bits_current + 1, result);
			}
		}

		void get_all_top(key_T& key,
		                 const uint32_t& key_bits_current,
		                 std::vector<std::tuple<key_T, uint32_t>>& result) const
		{
			if (value)
			{
				result.emplace_back(key, key_bits_current);
				return;
			}

			if (nexts[0])
			{
				nexts[0]->get_all_top(key, key_bits_current + 1, result);
			}

			if (nexts[1])
			{
				key.set_bit(key_bits_current, 1);
				nexts[1]->get_all_top(key, key_bits_current + 1, result);
				key.set_bit(key_bits_current, 0);
			}
		}

		void lookup(const key_T& key,
		            const uint32_t& key_bits,
		            const uint32_t& key_bits_current,
		            std::optional<std::tuple<value_T, uint32_t>>& result) const
		{
			if (value)
			{
				result = {*value, key_bits_current};
			}

			if (key_bits_current == key_bits)
			{
				/// nothing
			}
			else
			{
				auto* const& next = nexts[key.get_bit(key_bits_current)];

				if (!next)
				{
					return;
				}

				next->lookup(key, key_bits, key_bits_current + 1, result);
			}
		}

		void lookup_all(const key_T& key,
		                const uint32_t& key_bits,
		                const uint32_t& key_bits_current,
		                const std::function<void(const value_T&, const uint32_t)>& callback) const
		{
			if (value)
			{
				callback(*value, key_bits_current);
			}

			if (key_bits_current == key_bits)
			{
				return;
			}
			else
			{
				auto* const& next = nexts[key.get_bit(key_bits_current)];

				if (!next)
				{
					return;
				}

				next->lookup_all(key, key_bits, key_bits_current + 1, callback);
			}
		}

		void lookup_deep(key_T& key,
		                 const uint32_t& key_bits,
		                 const uint32_t& key_bits_current,
		                 const std::function<void(const key_T&, const uint32_t, const value_T&)>& callback,
		                 const std::optional<value_T>& value_prev) const
		{
			if (key_bits_current == key_bits)
			{
				if (value)
				{
					callback(key, key_bits_current, *value);
				}
				else if (value_prev)
				{
					callback(key, key_bits_current, *value_prev);
				}

				if (nexts[0])
				{
					nexts[0]->lookup_deep(key, key_bits, key_bits_current + 1, callback, std::nullopt);
				}

				if (nexts[1])
				{
					key.set_bit(key_bits_current, 1);
					nexts[1]->lookup_deep(key, key_bits, key_bits_current + 1, callback, std::nullopt);
					key.set_bit(key_bits_current, 0);
				}
			}
			else if (key_bits_current > key_bits)
			{
				if (value)
				{
					callback(key, key_bits_current, *value);
				}

				if (nexts[0])
				{
					nexts[0]->lookup_deep(key, key_bits, key_bits_current + 1, callback, std::nullopt);
				}

				if (nexts[1])
				{
					key.set_bit(key_bits_current, 1);
					nexts[1]->lookup_deep(key, key_bits, key_bits_current + 1, callback, std::nullopt);
					key.set_bit(key_bits_current, 0);
				}
			}
			else
			{
				auto* const& next = nexts[key.get_bit(key_bits_current)];

				if (!next)
				{
					if (value)
					{
						callback(key, key_bits, *value);
					}
					else if (value_prev)
					{
						callback(key, key_bits, *value_prev);
					}
					return;
				}

				if (value)
				{
					next->lookup_deep(key, key_bits, key_bits_current + 1, callback, value);
				}
				else
				{
					next->lookup_deep(key, key_bits, key_bits_current + 1, callback, value_prev);
				}
			}
		}

	public:
		std::optional<value_T> value;
		std::array<node_t*, 2> nexts;
	};

	node_t* root;
};

template<typename value_T>
class btree<ip_address_t, value_T>
{
public:
	void insert(const ip_prefix_t& prefix,
	            const value_T& value)
	{
		if (prefix.is_ipv4())
		{
			btree_v4.insert(prefix.get_ipv4().address(),
			                prefix.get_ipv4().mask(),
			                value);
		}
		else
		{
			btree_v6.insert(prefix.get_ipv6().address(),
			                prefix.get_ipv6().mask(),
			                value);
		}
	}

	void remove(const ip_prefix_t& prefix)
	{
		if (prefix.is_ipv4())
		{
			btree_v4.remove(prefix.get_ipv4().address(),
			                prefix.get_ipv4().mask());
		}
		else
		{
			btree_v6.remove(prefix.get_ipv6().address(),
			                prefix.get_ipv6().mask());
		}
	}

	void clear()
	{
		btree_v4.clear();
		btree_v6.clear();
	}

	std::optional<value_T> get(const ip_prefix_t& prefix) const
	{
		if (prefix.is_ipv4())
		{
			return btree_v4.get(prefix.get_ipv4().address(),
			                    prefix.get_ipv4().mask());
		}
		else
		{
			return btree_v6.get(prefix.get_ipv6().address(),
			                    prefix.get_ipv6().mask());
		}
	}

	[[nodiscard]] std::vector<ip_prefix_t> get_all_top() const
	{
		std::vector<ip_prefix_t> result;

		const auto top_v4 = btree_v4.get_all_top();
		for (const auto& [address, mask] : top_v4)
		{
			result.emplace_back(address, mask);
		}

		const auto top_v6 = btree_v6.get_all_top();
		for (const auto& [address, mask] : top_v6)
		{
			result.emplace_back(address, mask);
		}

		return result;
	}

	std::optional<std::tuple<value_T, uint32_t>> lookup(const ip_address_t& address) const
	{
		if (address.is_ipv4())
		{
			return btree_v4.lookup(address.get_ipv4(),
			                       32);
		}
		else
		{
			return btree_v6.lookup(address.get_ipv6(),
			                       128);
		}
	}

	std::optional<std::tuple<value_T, uint32_t>> lookup(const ip_prefix_t& prefix) const
	{
		if (prefix.is_ipv4())
		{
			return btree_v4.lookup(prefix.get_ipv4().address(),
			                       prefix.get_ipv4().mask());
		}
		else
		{
			return btree_v6.lookup(prefix.get_ipv6().address(),
			                       prefix.get_ipv6().mask());
		}
	}

	void lookup_all(const ip_prefix_t& prefix,
	                const std::function<void(const value_T&, const uint32_t)>& callback) const
	{
		if (prefix.is_ipv4())
		{
			btree_v4.lookup_all(prefix.get_ipv4().address(),
			                    prefix.get_ipv4().mask(),
			                    callback);
		}
		else
		{
			btree_v6.lookup_all(prefix.get_ipv6().address(),
			                    prefix.get_ipv6().mask(),
			                    callback);
		}
	}

	void lookup_deep(const ip_prefix_t& prefix,
	                 const std::function<void(const ip_prefix_t&, const value_T&)>& callback) const
	{
		if (prefix.is_ipv4())
		{
			btree_v4.lookup_deep(prefix.get_ipv4().address(),
			                     prefix.get_ipv4().mask(),
			                     [&callback](const ipv4_address_t& address, const uint32_t mask, const value_T& value) {
				                     callback({address, (uint8_t)mask}, value);
			                     });
		}
		else
		{
			btree_v6.lookup_deep(prefix.get_ipv6().address(),
			                     prefix.get_ipv6().mask(),
			                     [&callback](const ipv6_address_t& address, const uint32_t mask, const value_T& value) {
				                     callback({address, (uint8_t)mask}, value);
			                     });
		}
	}

protected:
	btree<ipv4_address_t, value_T> btree_v4;
	btree<ipv6_address_t, value_T> btree_v6;
};

}
