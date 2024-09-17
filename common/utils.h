
#pragma once

#include <type_traits>

namespace utils
{

template<typename>
struct always_false : std::false_type
{};

}
// namespace utils
