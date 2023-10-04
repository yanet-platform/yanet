#pragma once

#include "common/config.h"

#ifdef CONFIG_YADECAP_AUTOTEST

#include <stdint.h>
#include <unistd.h>

#define LATCH_USLEEP_CYCLE 50

struct debug_latch
{
	uint32_t locked;
};

extern struct debug_latch debug_latches[];

#define DEBUG_LATCH_WAIT(ID)                                         \
	do                                                           \
	{                                                            \
		struct debug_latch* latch = debug_latches + (int)ID; \
		while (latch->locked)                                \
		{                                                    \
			usleep(LATCH_USLEEP_CYCLE);                  \
		}                                                    \
	} while (0);

#define DEBUG_LATCH_UPDATE(ID, LOCKED)                               \
	do                                                           \
	{                                                            \
		struct debug_latch* latch = debug_latches + (int)ID; \
		latch->locked = LOCKED;                              \
	} while (0)

#else

#define DEBUG_LATCH_WAIT(ID) \
	do                   \
	{                    \
		(void)(ID);  \
	} while (0)
#define DEBUG_LATCH_UPDATE(ID, LOCKED) \
	do                             \
	{                              \
		(void)(ID);            \
		(void)(LOCKED);        \
	} while (0)

#endif
