#pragma once

#include <algorithm>
#include <array>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace utils
{

template<typename T, std::size_t Cap, bool UseExceptions = false>
class StaticVector
{
	using storage_t = std::aligned_storage_t<sizeof(T), alignof(T)>;
	std::array<storage_t, Cap> buf_;
	std::size_t len_ = 0;

	T* AddressOfIndex(std::size_t idx)
	{
		return std::launder(reinterpret_cast<T*>(&buf_[idx]));
	}

	const T* AddressOfIndex(std::size_t idx) const
	{
		return std::launder(reinterpret_cast<const T*>(&buf_[idx]));
	}

	void HandleOutOfRange()
	{
		if constexpr (UseExceptions)
		{
			throw std::out_of_range("");
		}
		else
		{
			std::abort();
		}
	}

	template<typename... Args>
	void PushBackUnsafe(Args&&... args)
	{
		new (AddressOfIndex(len_)) T(std::forward<Args>(args)...);
		++len_;
	}

	template<typename OtherVector>
	void PerElementTransfer(OtherVector&& other)
	{
		// If T is trivially copyable, use trivial copy
		if constexpr (std::is_trivially_copyable_v<T>)
		{
			std::copy(std::begin(other.buf_), std::begin(other.buf_) + other.len_, std::begin(buf_));
			len_ = other.len_;
		}
		else
		{
			clear();

			for (auto&& elem : other)
			{
				PushBackUnsafe(std::forward<decltype(elem)>(elem));
			}

			// If other is an rvalue, clear the original vector
			if constexpr (std::is_rvalue_reference_v<decltype(other)>)
			{
				other.clear();
			}
		}
	}

public:
	using iterator = T*;
	using const_iterator = const T*;

	StaticVector() = default;

	~StaticVector()
	{
		clear();
	}

	StaticVector(const StaticVector& other)
	{
		PerElementTransfer(other);
	}

	StaticVector(StaticVector&& other) noexcept
	{
		PerElementTransfer(std::move(other));
	}

	StaticVector& operator=(const StaticVector& other)
	{
		if (this != &other)
		{
			clear();
			PerElementTransfer(other);
		}
		return *this;
	}

	StaticVector& operator=(StaticVector&& other) noexcept
	{
		if (this != &other)
		{
			clear();
			PerElementTransfer(std::move(other));
		}
		return *this;
	}

	template<typename U>
	void push_back(U&& elem)
	{
		if (Full())
		{
			HandleOutOfRange();
		}
		PushBackUnsafe(std::forward<U>(elem));
	}

	template<typename... Args>
	void emplace_back(Args&&... args)
	{
		if (Full())
		{
			HandleOutOfRange();
		}
		PushBackUnsafe(std::forward<Args>(args)...);
	}

	void pop_back()
	{
		if (empty())
		{
			HandleOutOfRange();
		}
		at(--len_).~T();
	}

	T& operator[](std::size_t pos)
	{
		return *AddressOfIndex(pos);
	}

	const T& operator[](std::size_t pos) const
	{
		return *AddressOfIndex(pos);
	}

	T& at(std::size_t pos)
	{
		if (pos >= size())
		{
			HandleOutOfRange();
		}
		return *AddressOfIndex(pos);
	}

	const T& at(std::size_t pos) const
	{
		if (pos >= size())
		{
			HandleOutOfRange();
		}
		return *AddressOfIndex(pos);
	}

	iterator begin() { return AddressOfIndex(0); }
	iterator end() { return AddressOfIndex(size()); }
	const_iterator begin() const { return AddressOfIndex(0); }
	const_iterator end() const { return AddressOfIndex(size()); }
	const_iterator cbegin() const { return AddressOfIndex(0); }
	const_iterator cend() const { return AddressOfIndex(size()); }

	[[nodiscard]] bool empty() const { return size() == 0; }
	[[nodiscard]] constexpr std::size_t capacity() const { return Cap; }
	[[nodiscard]] std::size_t size() const { return len_; }
	[[nodiscard]] bool Full() const { return size() == capacity(); }

	// Clear the vector and destruct elements
	void clear()
	{
		if constexpr (std::is_trivially_destructible_v<T>)
		{
			len_ = 0;
		}
		else
		{
			while (!empty())
			{
				pop_back();
			}
		}
	}
};

} // namespace utils
