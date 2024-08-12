#pragma once
#include <algorithm>

#include <stdexcept>

namespace utils
{

#ifdef STATIC_VECTOR_USE_EXCEPTIONS
static constexpr bool USE_EXCEPTIONS = true;
#else
static constexpr bool USE_EXCEPTIONS = false;
#endif

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

	void TrivialCopy(const StaticVector& other)
	{
		std::copy(std::begin(other.buf_),
		          std::begin(other.buf_) + other.len_ * sizeof(T),
		          std::begin(buf_));
		len_ = other.len_;
	}

	void PerElementCopy(const StaticVector& other)
	{
		clear();
		for (const auto& elem : other)
		{
			PushBackUnsafe(elem);
		}
	}

	void PerElementCopy(StaticVector&& other)
	{
		clear();
		for (auto& elem : other)
		{
			PushBackUnsafe(std::move(elem));
		}
	}

	void HandleOutOfRange()
	{
		if constexpr (USE_EXCEPTIONS)
		{
			throw std::out_of_range("");
		}
		else
		{
			std::abort();
		}
	}

	void PushBackUnsafe(const T& elem)
	{
		new (AddressOfIndex(len_)) T(elem);
		++len_;
	}

	void PushBackUnsafe(T&& elem)
	{
		new (AddressOfIndex(len_)) T(std::move(elem));
		++len_;
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

		if constexpr (std::is_trivially_copyable_v<T>)
		{
			TrivialCopy(other);
		}
		else
		{
			PerElementMove(other);
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
		if constexpr (std::is_trivially_copyable_v<T>)
		{
			TrivialCopy(other);
		}
		else
		{
			PerElementCopy(other);
		}
		return *this;
	}

	void push_back(const T& elem)
	{
		if (Full())
		{
			HandleOutOfRange();
			return;
		}
		PushBackUnsafe(elem);
	}

	void push_back(T&& elem)
	{
		if (Full())
		{
			HandleOutOfRange();
			return;
		}
		PushBackUnsafe(std::move(elem));
	}

	template<typename... Args>
	void emplace_back(Args&&... args)
	{
		new (AddressOfIndex(len_)) T(std::forward<Args>(args)...);
		++len_;
	}

	void pop_back()
	{
		if (empty())
		{
			HandleOutOfRange();
			return;
		}
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
			HandleOutOfRange();
			abort();
		}
		return *AddressOfIndex(pos);
		// return reinterpret_cast<T&>(buf_[pos * sizeof(T)]);
	}

	const T& at(std::size_t pos) const
	{
		if (pos >= size())
		{
			HandleOutOfRange();
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

	std::size_t size() const { return len_; }
	bool Full() const { return size() == capacity(); }
};

} // namespace utils
