#pragma once
#include <array>

#include "utils.h"

namespace utils
{

template<typename T, std::size_t Cap>
class StaticVector
{
	alignas(T) unsigned char buf_[sizeof(T[Cap])];
	std::size_t len_ = 0;

	T* AddressOfIndex(std::size_t idx)
	{
		return reinterpret_cast<T*>(buf_) + idx;
	}

	const T* AddressOfIndex(std::size_t idx) const
	{
		return reinterpret_cast<const T*>(buf_) + idx;
	}

public:
	using iterator = T*;
	using const_iterator = const T*;
	StaticVector() = default;
	StaticVector(StaticVector&& other)
	{
		*this = std::move(other);
	}
	StaticVector& operator=(StaticVector&& other)
	{
		if (this == &other)
		{
			return *this;
		}
		clear();
		for (auto& elem : other)
		{
			push_back(std::move(elem));
		}
		return *this;
	}
	StaticVector(const StaticVector& other)
	{
		*this = other;
	}
	StaticVector& operator=(const StaticVector& other)
	{
		if (this == &other)
		{
			return *this;
		}
		clear();
		for (const auto& elem : other)
		{
			push_back(elem);
		}
		return *this;
	}
	void push_back(const T& elem)
	{
		if (Full())
		{
			abort();
		}
		new (AddressOfIndex(len_)) T(elem);
		++len_;
	}
	void push_back(T&& elem)
	{
		if (Full())
		{
			abort();
		}
		new (AddressOfIndex(len_)) T(std::move(elem));
		++len_;
	}
	template<typename... Args>
	void emplace_back(Args&&... args)
	{
		new (AddressOfIndex(len_)) T(std::forward<Args>(args)...);
		++len_;
	}
	void pop_back()
	{
		at(--len_).~T();
	}
	T& operator[](std::size_t pos)
	{
		return *AddressOfIndex(pos);
		// return reinterpret_cast<T&>(buf_[pos * sizeof(T)]);
	}
	const T& operator[](std::size_t pos) const
	{
		return *AddressOfIndex(pos);
	}
	T& at(std::size_t pos)
	{
		if (pos >= size())
		{
			abort();
		}
		return *AddressOfIndex(pos);
		// return reinterpret_cast<T&>(buf_[pos * sizeof(T)]);
	}
	const T& at(std::size_t pos) const
	{
		if (pos >= size())
		{
			abort();
		}
		return *AddressOfIndex(pos);
	}
	iterator begin() { return AddressOfIndex(0); }
	iterator end() { return AddressOfIndex(size()); }
	const_iterator begin() const { return AddressOfIndex(0); }
	const_iterator end() const { return AddressOfIndex(size()); }
	const_iterator cbegin() const { return AddressOfIndex(0); }
	const_iterator cend() const { return AddressOfIndex(size()); }
	[[nodiscard]] bool empty() const
	{
		return size() == 0;
	}
	constexpr std::size_t capacity() const { return Cap; }
	void clear()
	{
		while (!empty())
		{
			pop_back();
		}
	}
	std::size_t size() const { return len_; }
	bool Full() const { return size() == capacity(); }
};

} // namespace utils
