#pragma once

#include <array>
#include <atomic>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <vector>

template<typename Type,
         typename Type_Update_Result = bool>
class generation_manager
{
public:
	class generation_unique
	{
	public:
		generation_unique(std::shared_mutex* mutex,
		                  generation_manager<Type>* generation_manager) :
		        mutex(mutex),
		        generation_manager(generation_manager)
		{
			mutex->lock();
		}

		~generation_unique()
		{
			mutex->unlock();
		}

		generation_unique(const generation_unique&) = delete;
		generation_unique(generation_unique&&) = delete;
		generation_unique& operator=(const generation_unique&) = delete;
		generation_unique& operator=(generation_unique&&) = delete;

		Type& operator*()
		{
			return generation_manager->generations[generation_manager->id ^ 1];
		}

		const Type& operator*() const
		{
			return generation_manager->generations[generation_manager->id ^ 1];
		}

		Type* operator->()
		{
			return &(generation_manager->generations[generation_manager->id ^ 1]);
		}

		const Type* operator->() const
		{
			return &(generation_manager->generations[generation_manager->id ^ 1]);
		}

	protected:
		std::shared_mutex* mutex;
		::generation_manager<Type>* generation_manager;
	};

	class generation_shared
	{
	public:
		generation_shared(std::shared_mutex* mutex,
		                  const generation_manager<Type>* generation_manager) :
		        mutex(mutex),
		        generation_manager(generation_manager)
		{
			mutex->lock_shared();
		}

		~generation_shared()
		{
			mutex->unlock_shared();
		}

		generation_shared(const generation_shared&) = delete;
		generation_shared(generation_shared&&) = delete;
		generation_shared& operator=(const generation_shared&) = delete;
		generation_shared& operator=(generation_shared&&) = delete;

		const Type& operator*() const
		{
			return generation_manager->generations[generation_manager->id];
		}

		const Type* operator->() const
		{
			return &(generation_manager->generations[generation_manager->id]);
		}

	protected:
		std::shared_mutex* mutex;
		const ::generation_manager<Type>* generation_manager;
	};

public:
	generation_manager() :
	        id(0)
	{
	}

	void current_lock() const
	{
		current_mutex.lock_shared();
	}

	void current_unlock() const
	{
		current_mutex.unlock_shared();
	}

	[[nodiscard]] std::shared_lock<std::shared_mutex> current_lock_guard() const
	{
		return std::move(std::shared_lock(current_mutex));
	}

	const Type& current() const
	{
		return generations[id];
	}

	/** dangerous
	generation_shared current_shared() const
	{
		return generation_shared(&current_mutex, this);
	}
	*/

	void next_lock()
	{
		next_mutex.lock();
	}

	void next_unlock()
	{
		next_mutex.unlock();
	}

	Type& next()
	{
		return generations[id ^ 1];
	}

	/** dangerous
	generation_unique next_unique()
	{
		return generation_unique(&next_mutex, this);
	}
	*/

	void switch_generation()
	{
		{
			std::unique_lock current_lock(current_mutex);
			id ^= 1;
		}

		generations[id ^ 1] = {}; ///< @todo: gc
	}

	void switch_generation_without_gc()
	{
		std::unique_lock current_lock(current_mutex);
		id ^= 1;
	}

	/** @todo
	void gc()
	{
	}
	*/

	/// apply function for both generation
	template<typename function_t>
	void fill(const function_t& function)
	{
		next_lock();
		function(next());
		switch_generation_without_gc();
		function(next());
		next_unlock();
	}

	/// apply function for next generation and insert in requests queue
	template<typename function_t>
	Type_Update_Result update(const function_t& function)
	{
		next_lock();
		auto result = function(next());
		requests.emplace_back(function);
		next_unlock();
		return result;
	}

	/// switch generation and apply all previous requests for next generation
	template<typename wait_function_t>
	void switch_generation_with_update(const wait_function_t& wait_function)
	{
		next_lock();
		if (requests.size())
		{
			/// update current pointer
			switch_generation_without_gc();

			/// wait all thread who used previous generation
			wait_function();

			/// apply all previous requests for next generation
			for (const auto& function : requests)
			{
				function(next());
			}
			requests.clear();
		}
		next_unlock();
	}

protected:
	mutable std::shared_mutex current_mutex;
	mutable std::shared_mutex next_mutex;

	std::atomic<uint32_t> id;
	std::array<Type, 2> generations;

	std::vector<std::function<Type_Update_Result(Type&)>> requests;
};
