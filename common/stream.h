#pragma once

#include <inttypes.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

namespace common
{

// TODO: This class offers serialization/deserialization of objects, but it is too restrictive.
// Due to the pop method interface, which returns objects by reference in an argument,
// we cannot use this with non DefaultConstructible objects.
// This means that even though we serialize an object and want to deserialize it by
// creating an object directly, without needing to first create a default one,
// we are unable to do so.
class stream_in_t
{
public:
	using integer_t = uint64_t;

public:
	stream_in_t(const std::vector<uint8_t>& buffer);

	template<typename TType>
	inline void pop(TType& value);

private:
	inline void pop(char* buffer, uint64_t bufferSize);

public:
	inline void pop(std::string& value);
	inline void pop(std::vector<uint8_t>& value);

	template<typename TFirst, typename TSecond>
	inline void pop(std::pair<TFirst, TSecond>& pair);

	template<typename T, std::size_t Size>
	inline void pop(T (&value)[Size]);

	template<typename TType, std::size_t TSize>
	inline void pop(std::array<TType, TSize>& array);

	template<typename TType>
	inline void pop(std::vector<TType>& vector);

	template<typename TFirst, typename TSecond, typename TCompare>
	inline void pop(std::map<TFirst, TSecond, TCompare>& map);

	template<typename TFirst, typename TSecond, typename TCompare>
	inline void pop(std::unordered_map<TFirst, TSecond, TCompare>& unordered_map);

	template<typename... TArgs>
	inline void pop(std::tuple<TArgs...>& tuple);

	template<typename... TArgs>
	inline void pop(std::variant<TArgs...>& variant);

	template<typename TType>
	inline void pop(std::set<TType>& set);

	template<typename TType>
	inline void pop(std::unordered_set<TType>& set);

	template<typename TType>
	inline void pop(std::optional<TType>& optional);

	template<typename TType>
	inline void pop(std::shared_ptr<TType>& pointer);

	inline bool isFailed();

protected:
	template<size_t TTupleIndex, typename... TArgs>
	inline void popTuple(std::tuple<TArgs...>& tuple);

	template<size_t TVariantIndex, typename... TArgs>
	inline void popVariant(std::variant<TArgs...>& variant, uint32_t index);

protected:
	const std::vector<uint8_t>& inBuffer;
	uint64_t inPosition;
	bool failed;
};

//

class stream_out_t
{
public:
	using integer_t = uint64_t;

public:
	stream_out_t();

	template<typename TType>
	inline void push(const TType& value);

private:
	inline void push(const char* buffer, uint64_t bufferSize);

public:
	inline void push(const std::string& value);
	inline void push(const std::vector<uint8_t>& value);

	/// @todo
	template<typename TFirst, typename TSecond>
	inline void push(const std::pair<TFirst, TSecond>& pair)
	{
		push(pair.first);
		push(pair.second);
	}

	template<typename T, std::size_t Size>
	inline void push(const T (&array)[Size])
	{
		for (const auto& e : array)
		{
			push(e);
		}
	}

	template<typename TType, std::size_t TSize>
	inline void push(const std::array<TType, TSize>& array)
	{
		for (std::size_t i = 0; i < TSize; i++)
		{
			push(array[i]);
		}
	}

	template<typename TType>
	inline void push(const std::vector<TType>& vector)
	{
		integer_t size = vector.size();
		push(size);
		for (integer_t i = 0; i < size; i++)
		{
			push(vector[i]);
		}
	}

	template<typename TType>
	inline void push(std::vector<TType>&& vector)
	{
		integer_t size = vector.size();
		push(size);
		for (integer_t i = 0; i < size; i++)
		{
			push(std::move(vector[i]));
		}
		vector.clear();
	}

	template<typename TFirst, typename TSecond, typename TCompare>
	inline void push(const std::map<TFirst, TSecond, TCompare>& map)
	{
		integer_t size = map.size();
		push(size);
		for (auto& iter : map)
		{
			push(iter.first);
			push(iter.second);
		}
	}

	template<typename TFirst, typename TSecond, typename TCompare>
	inline void push(const std::unordered_map<TFirst, TSecond, TCompare>& unordered_map)
	{
		integer_t size = unordered_map.size();
		push(size);
		for (auto& iter : unordered_map)
		{
			push(iter.first);
			push(iter.second);
		}
	}

	template<typename... TArgs>
	inline void push(const std::tuple<TArgs...>& tuple)
	{
		pushTuple<0, TArgs...>(tuple);
	}

	template<typename... TArgs>
	inline void push(std::tuple<TArgs...>&& tuple)
	{
		pushTupleMove<0, TArgs...>(std::move(tuple));
	}

	template<typename... TArgs>
	inline void push(const std::variant<TArgs...>& variant)
	{
		integer_t index = variant.index();
		push(index);
		std::visit([&](auto&& arg) { push(arg); }, variant);
	}

	template<typename... TArgs>
	inline void push(std::variant<TArgs...>&& variant)
	{
		integer_t index = variant.index();
		push(index);
		std::visit([&](auto&& arg) { push(std::move(arg)); }, variant);
	}

	template<typename TType>
	inline void push(const std::set<TType>& set)
	{
		integer_t size = set.size();
		push(size);
		for (auto& value : set)
		{
			push(value);
		}
	}

	template<typename TType>
	inline void push(const std::unordered_set<TType>& unordered_set)
	{
		integer_t size = unordered_set.size();
		push(size);
		for (auto& value : unordered_set)
		{
			push(value);
		}
	}

	template<typename TType>
	inline void push(const std::optional<TType>& optional)
	{
		if (optional)
		{
			push((uint8_t)1);
			push(*optional);
		}
		else
		{
			push((uint8_t)0);
		}
	}

	template<typename TType>
	inline void push(const std::shared_ptr<TType>& pointer)
	{
		push(*pointer.get());
	}

	inline const std::vector<uint8_t>& getBuffer()
	{
		return outBuffer;
	}

protected:
	template<size_t TTupleIndex, typename... TArgs>
	inline void pushTuple(const std::tuple<TArgs...>& tuple)
	{
		if constexpr (TTupleIndex < sizeof...(TArgs))
		{
			push(std::get<TTupleIndex>(tuple));
			pushTuple<TTupleIndex + 1>(tuple);
		}
	}

	template<size_t TTupleIndex, typename... TArgs>
	inline void pushTupleMove(std::tuple<TArgs...>&& tuple)
	{
		if constexpr (TTupleIndex < sizeof...(TArgs))
		{
			push(std::move(std::get<TTupleIndex>(tuple)));
			pushTupleMove<TTupleIndex + 1>(std::move(tuple));
		}
	}

private:
	std::vector<uint8_t> outBuffer;
};

//

inline stream_in_t::stream_in_t(const std::vector<uint8_t>& buffer) :
        inBuffer(buffer),
        inPosition(0),
        failed(false)
{
}

template<typename TType>
inline void stream_in_t::pop(TType& value)
{
	if constexpr (std::is_trivially_copyable_v<TType>)
	{
		if (inBuffer.size() - inPosition < sizeof(TType))
		{
			value = TType{};
			inPosition = this->inBuffer.size();
			failed = true;
			return;
		}

		value = reinterpret_cast<const TType&>(inBuffer[inPosition]);

		inPosition += sizeof(TType);
	}
	else
	{
		value.pop(*this);
	}
}

inline void stream_in_t::pop(char* buffer, uint64_t bufferSize)
{
	if (this->inBuffer.size() - inPosition < bufferSize)
	{
		inPosition = this->inBuffer.size();
		failed = true;
		return;
	}

	if (bufferSize == 0)
	{
		return;
	}

	auto bufferStart = inBuffer.begin() + inPosition;

	std::copy(bufferStart, bufferStart + bufferSize, buffer);
	inPosition += bufferSize;
}

inline void stream_in_t::pop(std::string& value)
{
	std::string::size_type size;
	pop(size);

	if (this->inBuffer.size() - inPosition < size)
	{
		inPosition = this->inBuffer.size();
		failed = true;
		return;
	}

	if (size == 0)
	{
		return;
	}

	value.assign(reinterpret_cast<const char*>(&this->inBuffer[inPosition]), size);
	inPosition += size;
}

inline void stream_in_t::pop(std::vector<uint8_t>& value)
{
	integer_t size = 0;

	pop(size);

	value.reserve(size);
	value.resize(size);
	pop(reinterpret_cast<char*>(&value[0]), size);
}

template<typename TFirst, typename TSecond>
inline void stream_in_t::pop(std::pair<TFirst, TSecond>& pair)
{
	pop(pair.first);
	pop(pair.second);
}

template<typename T, std::size_t Size>
inline void stream_in_t::pop(T (&array)[Size])
{
	for (auto& e : array)
	{
		pop(e);
	}
}

template<typename TType, std::size_t TSize>
inline void stream_in_t::pop(std::array<TType, TSize>& array)
{
	for (std::size_t i = 0; i < TSize; i++)
	{
		pop(array[i]);
	}
}

template<typename TType>
inline void stream_in_t::pop(std::vector<TType>& vector)
{
	integer_t count = 0;

	pop(count);

	vector.resize(count);
	for (integer_t i = 0; i < count; i++)
	{
		pop(vector[i]);
		if (isFailed())
		{
			return;
		}
	}
}

template<typename TFirst, typename TSecond, typename TCompare>
inline void stream_in_t::pop(std::map<TFirst, TSecond, TCompare>& map)
{
	integer_t count = 0;

	pop(count);

	for (integer_t i = 0; i < count; i++)
	{
		TFirst firstValue;
		pop(firstValue);
		pop(map[firstValue]);
	}
}

template<typename TFirst, typename TSecond, typename TCompare>
inline void stream_in_t::pop(std::unordered_map<TFirst, TSecond, TCompare>& unordered_map)
{
	integer_t count = 0;

	pop(count);

	for (integer_t i = 0; i < count; i++)
	{
		TFirst firstValue;
		pop(firstValue);
		pop(unordered_map[firstValue]);
	}
}

template<typename... TArgs>
inline void stream_in_t::pop(std::tuple<TArgs...>& tuple)
{
	popTuple<0>(tuple);
}

template<typename... TArgs>
inline void stream_in_t::pop(std::variant<TArgs...>& variant)
{
	integer_t index = 0;

	pop(index);
	if (isFailed())
	{
		return;
	}

	popVariant<0>(variant, index);
}

template<typename TType>
inline void stream_in_t::pop(std::set<TType>& set)
{
	integer_t count = 0;

	pop(count);

	for (integer_t i = 0; i < count; i++)
	{
		TType value;
		pop(value);
		set.emplace(value);
	}
}

template<typename TType>
inline void stream_in_t::pop(std::unordered_set<TType>& unordered_set)
{
	integer_t count = 0;

	pop(count);

	for (integer_t i = 0; i < count; i++)
	{
		TType value;
		pop(value);
		unordered_set.emplace(value);
	}
}

template<typename TType>
inline void stream_in_t::pop(std::optional<TType>& optional)
{
	uint8_t flag = 0;

	pop(flag);

	if (flag)
	{
		TType value;
		pop(value);
		optional = value;
	}
}

template<typename TType>
inline void stream_in_t::pop(std::shared_ptr<TType>& pointer)
{
	pointer = std::make_shared<TType>();
	pop(*pointer.get());
}

inline bool stream_in_t::isFailed()
{
	return failed;
}

template<size_t TTupleIndex, typename... TArgs>
inline void stream_in_t::popTuple(std::tuple<TArgs...>& tuple)
{
	if constexpr (TTupleIndex < sizeof...(TArgs))
	{
		pop(std::get<TTupleIndex>(tuple));
		popTuple<TTupleIndex + 1>(tuple);
	}
}

template<size_t TVariantIndex, typename... TArgs>
inline void stream_in_t::popVariant(std::variant<TArgs...>& variant,
                                    uint32_t index)
{
	if constexpr (TVariantIndex < sizeof...(TArgs))
	{
		if (index == TVariantIndex)
		{
			typename std::tuple_element<TVariantIndex, std::tuple<TArgs...>>::type value;

			pop(value);
			if (isFailed())
			{
				return;
			}

			variant = value;
		}
		else
		{
			popVariant<TVariantIndex + 1>(variant, index);
		}
	}
	else
	{
		inPosition = this->inBuffer.size();
		failed = true;
	}
}

//

inline stream_out_t::stream_out_t()
{
}

template<typename TType>
inline void stream_out_t::push(const TType& value)
{
	using ByteArray = const uint8_t(&)[sizeof(TType)];
	if constexpr (std::is_trivially_copyable_v<TType>)
	{
		auto& data = reinterpret_cast<ByteArray>(value);
		outBuffer.insert(outBuffer.end(), std::begin(data), std::end(data));
	}
	else
	{
		value.push(*this);
	}
}

inline void stream_out_t::push(const char* buffer, uint64_t bufferSize)
{
	if (bufferSize == 0)
	{
		return;
	}
	outBuffer.insert(outBuffer.end(), buffer, buffer + bufferSize);
}

inline void stream_out_t::push(const std::string& value)
{
	push(value.length());
	push(value.c_str(), value.length());
}

inline void stream_out_t::push(const std::vector<uint8_t>& value)
{
	integer_t size = value.size();
	push(size);
	push(reinterpret_cast<const char*>(value.data()), size);
}

}
