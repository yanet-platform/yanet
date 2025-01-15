#pragma once

#include <functional>
#include <numeric>
#include <stdexcept>

namespace acl::compiler
{

/**
 * A multi-dimensional table specialized to a fixed dimension.
 * Dimension is set at compile time.
 *
 * This class stores the data in a single (flattened) `std::vector<ValueType>`
 * along with a "stride" array for efficient indexing. It provides:
 *
 *   - prepare(sizes...) to set the dimension sizes & allocate storage
 *   - operator()(i1, i2, ..., iN) or operator()(array_of_indices)
 *       for element access with bounds checking
 *   - for_each(callback) to iterate over non-zero elements
 *   - fill(value) to set all elements to a given value
 *   - clear() to reset everything
 */
template<typename ValueType, unsigned int Dimension>
class NDArray
{
public:
	using DimensionArray = std::array<std::size_t, Dimension>;

private:
	static_assert(Dimension > 0, "Dimension must be greater than zero");

	/** Flattened storage of table data */
	std::vector<ValueType> values_;
	/** Sizes of each dimension */
	DimensionArray sizes_{};
	/**
	 * Strides for each dimension in row-major style:
	 * stride_[dim] = product of sizes_[dim+1..Dimension-1]
	 */
	DimensionArray strides_{};

	/**
	 * Compute the flattened index from an array of dimension indices,
	 * performing range-checks along the way.
	 */
	[[nodiscard]]
	std::size_t FlattenIndex(const DimensionArray& idx) const
	{
		std::size_t flat_idx = 0;
		for (unsigned int dim = 0; dim < Dimension; ++dim)
		{
			if (idx[dim] >= sizes_[dim])
			{
				throw std::out_of_range("NDArray: dimension index out of range");
			}
			flat_idx += idx[dim] * strides_[dim];
		}
		return flat_idx;
	}

	/**
	 * Inverse of flatten_index: fill `keys` with the dimension indices
	 * corresponding to `flat_index`.
	 */
	void UnflattenIndex(DimensionArray& keys, std::size_t flat_index) const
	{
		for (int dim = Dimension - 1; dim >= 0; --dim)
		{
			keys[dim] = flat_index % sizes_[dim];
			flat_index /= sizes_[dim];
		}
	}

	/**
	 * Compute `strides_` from the current `sizes_`.
	 *
	 * If sizes = [D0, D1, D2, ..., D(N-1)], then:
	 *   strides_[N-1] = 1
	 *   strides_[N-2] = D(N-1)
	 *   strides_[N-3] = D(N-2)*D(N-1)
	 *   ...
	 */
	void ComputeStrides()
	{
		if (Dimension == 0)
			return; // no dimensions, trivial

		strides_[Dimension - 1] = 1;
		for (int i = Dimension - 2; i >= 0; --i)
		{
			strides_[i] = strides_[i + 1] * sizes_[i + 1];
		}
	}

public:
	/**
	 * Reset the array to empty with all sizes = 0.
	 */
	void Clear()
	{
		values_.clear();
		sizes_.fill(0);
		strides_.fill(0);
	}

	/**
	 * Prepare the array, setting the size of each dimension and
	 * allocating enough space in `values_`.
	 *
	 * @param sizes variadic list of dimension sizes, must match `Dimension`.
	 */
	template<typename... SizeTs,
	         std::enable_if_t<sizeof...(SizeTs) == Dimension, bool> = false>
	void Prepare(SizeTs... sizes)
	{
		sizes_ = {static_cast<std::size_t>(sizes)...};

		std::size_t total = std::accumulate(sizes_.begin(), sizes_.end(), std::size_t{1}, std::multiplies<>{});

		ComputeStrides();
		values_.assign(total, ValueType{});
	}

	/**
	 * @return True if the array has zero capacity (i.e. if any dimension is zero).
	 */
	[[nodiscard]]
	bool Empty() const noexcept
	{
		return values_.empty();
	}

	/**
	 * @return The total number of elements in the NDArray (product of all dimension sizes).
	 */
	[[nodiscard]]
	std::size_t Size() const noexcept
	{
		return values_.size();
	}

	/**
	 * @return The sizes of each dimension as an std::array.
	 */
	[[nodiscard]]
	const DimensionArray& Sizes() const noexcept
	{
		return sizes_;
	}

	/**
	 * Fill the entire storage with the given value.
	 */
	void Fill(const ValueType& value)
	{
		std::fill(values_.begin(), values_.end(), value);
	}

	/**
	 * Provides read-only access to an element by multi-dimensional indices.
	 *
	 * @param indexes Array of dimension indices.
	 * @return A const reference to the requested element.
	 */
	[[nodiscard]]
	const ValueType& operator()(const DimensionArray& indexes) const
	{
		return values_.at(FlattenIndex(indexes));
	}

	/**
	 * Provides read-write access to an element by multi-dimensional indices.
	 *
	 * @param indexes Array of dimension indices.
	 * @return A reference to the requested element.
	 */
	ValueType& operator()(const DimensionArray& indexes)
	{
		return values_.at(FlattenIndex(indexes));
	}

	/**
	 * Overload for convenience: pass indices variadically rather than as an array.
	 * This enables code like table(i, j, k) instead of table({i, j, k}).
	 */
	template<typename... IndexTs,
	         std::enable_if_t<sizeof...(IndexTs) == Dimension, bool> = false>
	ValueType& operator()(IndexTs... indices)
	{
		DimensionArray idx = {static_cast<std::size_t>(indices)...};
		return (*this)(idx);
	}

	template<typename... IndexTs,
	         std::enable_if_t<sizeof...(IndexTs) == Dimension, bool> = false>
	const ValueType& operator()(IndexTs... indices) const
	{
		DimensionArray idx = {static_cast<std::size_t>(indices)...};
		return (*this)(idx);
	}

	/**
	 * Return the underlying flattened storage (read-only).
	 */
	[[nodiscard]]
	const std::vector<ValueType>& Values() const noexcept
	{
		return values_;
	}

	/**
	 * Return the underlying flattened storage (modifiable).
	 */
	[[nodiscard]]
	std::vector<ValueType>& Values() noexcept
	{
		return values_;
	}

	/**
	 * Iterate over all non-zero elements and invoke `callback`.
	 *
	 * @param callback  A callable with signature: void(const DimensionArray&, const ValueType&)
	 */
	template<typename Callback>
	void ForEach(Callback&& callback) const
	{
		if (Empty())
			return;

		DimensionArray keys;
		const std::size_t n = values_.size();
		for (std::size_t i = 0; i < n; ++i)
		{
			const ValueType& val = values_[i];
			if (val != ValueType{})
			{
				UnflattenIndex(keys, i);
				// pass dimension indices and the value to callback
				std::forward<Callback>(callback)(keys, val);
			}
		}
	}
};

} // namespace acl::compiler
