#include "debug_latch.h"

#include "common/idp.h"

#ifdef CONFIG_YADECAP_AUTOTEST

struct debug_latch debug_latches[(uint32_t)(common::idp::debug_latch_update::id::size)];

#endif
