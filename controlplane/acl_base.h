#pragma once

#include "common/type.h"
#include <vector>

using GroupIds = std::vector<tAclGroupId>;
using FilterIds = std::vector<tAclFilterId>;
using RuleIds = std::vector<tAclRuleId>;

namespace acl
{
class compiler_t;
}
