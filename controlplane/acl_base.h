#pragma once

#include <map>
#include <set>
#include <unordered_map>

#include <cinttypes>

#include "common/ankerl/unordered_dense.h"
#include "common/emhash/hash_table7.hpp"

using tAclGroupId = uint32_t;

// TODO: check another maps/hashes. Note that they should work with gcc 7.5 on Ubuntu18
template<typename Key, typename Value>
using FlatMap = emhash7::HashMap<Key, Value>;

template<typename Key>
using FlatSet = ankerl::unordered_dense::set<Key>;

namespace acl
{
class compiler_t;
}
