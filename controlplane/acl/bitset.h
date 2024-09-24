#pragma once

#include <cstdint>
#include <string_view>
#include <tuple>
#include <vector>

#ifdef ACL_DEBUG
#include <string>
#endif

namespace acl
{

/**
 * The %bitset_t class represents a sequence of bits.
 */
struct bitset_t
{
public:
	void insert(size_t i)
	{
		vals[i / 64] |= ((uint64_t)(1) << (i % 64));
		first_one = std::min(first_one, i / 64);
	}

	bool operator[](size_t i) const
	{

		return (vals[i / 64] & ((uint64_t)(1) << (i % 64))) != 0;
	}

	[[nodiscard]] bool empty() const
	{
		return first_one == size;
	}

#ifdef ACL_DEBUG
	void print() const
	{
		printf("%s", to_string().c_str());
	}

	[[nodiscard]] std::string to_string() const
	{
		std::string out;
		for (size_t i = 0; i < size; ++i)
		{
			uint64_t v = vals[i];
			for (unsigned j = 0; j < 64; ++j)
			{
				if (v & ((uint64_t)(1) << j))
				{
					out += std::to_string((i * 64) + j) + " ";
				}
			}
		}
		return out;
	}
#endif

	bitset_t& operator|=(bitset_t const& other)
	{
		if (other.empty())
		{
			return *this;
		}
		first_one = start(other);
		for (size_t i = other.first_one; i < size; ++i)
		{
			vals[i] |= other.vals[i];
		}

		return *this;
	}

	bitset_t& operator&=(bitset_t const& other)
	{
		if (empty())
		{
			return *this;
		}

		auto f = first_one;
		first_one = size;
		for (size_t i = f; i < size; ++i)
		{
			vals[i] &= other.vals[i];
			if (vals[i] != 0 && first_one == size)
			{
				first_one = i;
			}
		}

		return *this;
	}

	friend bitset_t operator&(const bitset_t& rs1, const bitset_t& rs2)
	{
		bitset_t r = rs1;

		return r &= rs2;
	}

	friend bool operator==(const bitset_t& p1, const bitset_t& p2)
	{
		for (size_t i = p1.start(p2); i < p1.size; ++i)
		{
			if (p1.vals[i] != p2.vals[i])
			{
				return false;
			}
		}

		return true;
	}

	friend bool operator!=(const bitset_t& p1, const bitset_t& p2)
	{
		return !(p1 == p2);
	}

	[[nodiscard]] std::tuple<size_t, bool> minAnd(const bitset_t& p) const
	{
		for (size_t i = std::max(first_one, p.first_one); i < size; ++i)
		{
			auto val = vals[i] & p.vals[i];
			if (val)
			{
				return {(i * 64) + __builtin_ffsll(val) - 1, true};
			}
		}

		return {0, false};
	}

	[[nodiscard]] std::tuple<size_t, bool> minAnd(const bitset_t& p1,
	                                const bitset_t& p2) const
	{
		for (size_t i = std::max(std::max(first_one, p1.first_one), p2.first_one); i < size; ++i)
		{
			auto val = vals[i] & p1.vals[i] & p2.vals[i];
			if (val)
			{
				return {(i * 64) + __builtin_ffsll(val) - 1, true};
			}
		}

		return {0, false};
	}

	[[nodiscard]] bool emptyAnd(const bitset_t& p1) const
	{
		for (size_t i = std::max(first_one, p1.first_one); i < size; ++i)
		{
			if (vals[i] & p1.vals[i])
			{
				return false;
			}
		}

		return true;
	}

private:
	[[nodiscard]] size_t start(const bitset_t& p1) const
	{
		return std::min(first_one, p1.first_one);
	}

private:
	size_t size;
	size_t first_one;

	std::vector<uint64_t> vals;

	friend struct std::hash<bitset_t>;

public:
	bitset_t(size_t count) :
	        size((count + 63) / 64), first_one(size), vals(size, 0)
	{
	}

	bitset_t(const bitset_t& o) = default;
	bitset_t& operator=(const bitset_t&) = default;

	bitset_t(bitset_t&& o) :
	        size(o.size), first_one(o.first_one), vals(std::move(o.vals))
	{
		o.size = 0;
		o.first_one = 0;
	}

	bitset_t& operator=(bitset_t&& o)
	{
		if (this != &o)
		{
			size = o.size;
			first_one = o.first_one;
			vals = std::move(o.vals);
			o.size = 0;
			o.first_one = 0;
		}

		return *this;
	}
};

} //namespace acl

namespace std
{
template<>
struct hash<acl::bitset_t>
{
	size_t operator()(const acl::bitset_t& b) const noexcept
	{
		return std::hash<std::string_view>()(std::string_view(reinterpret_cast<const char*>(b.vals.data()), b.size * 8));
	}
};
}
