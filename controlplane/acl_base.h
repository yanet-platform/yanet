#pragma once

#include <map>
#include <set>
#include <unordered_map>

#include <cinttypes>

using tAclGroupId = uint32_t;

#if defined(CUSTOM_HASH_STRUCTURES)
#include "hash_table7.hpp"
#include "unordered_dense.h"

// TODO: check another maps/hashes. Note that they should work with gcc 7.5 on Ubuntu18
template<typename Key, typename Value>
using FlatMap = emhash7::HashMap<Key, Value>;
template<typename Key>
using FlatSet = ankerl::unordered_dense::set<Key>;
#else
#include <unordered_map>
#include <unordered_set>

template<typename Key, typename Value>
using FlatMap = std::unordered_map<Key, Value>;
template<typename Key>
using FlatSet = std::unordered_set<Key>;
#endif

namespace acl
{
class compiler_t;
}
