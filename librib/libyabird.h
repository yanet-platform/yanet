#ifndef _LIBYABIRD_H_
#define _LIBYABIRD_H_

#ifdef __cplusplus
/*
 * Simple LIST implementation used in bird2.
 * There are only required for C++ libyabird types and macros.
 */

extern "C"
{
	typedef struct node
	{
		struct node *next, *prev;
	} node;

	typedef union list
	{
		struct
		{
			struct node head_node;
			void* head_padding;
		};
		struct
		{
			void* tail_padding;
			struct node tail_node;
		};
		struct
		{
			struct node* head;
			struct node* null;
			struct node* tail;
		};
	} list;

#define NODE (node*)
#define HEAD(l) ((l).head)
#define TAIL(l) ((l).tail)
#define NODE_NEXT(n) ((n)->next)
#define NODE_VALID(n) ((n)->next)
#define WALK_LIST(n, l) for (n = HEAD(l); NODE_VALID(n); n = NODE_NEXT(n))
#define EMPTY_LIST(l) (!(l).head->next)
};

extern "C"
{
#endif /* __cplusplus */
	typedef struct yanet_prefix
	{
		node n;
		const char* prefix;
		uint32_t path_id;
	} yanet_prefix_t;

	typedef struct yanet_u32
	{
		uint32_t count;
		uint32_t data[0];
	} yanet_u32_t;

	typedef struct yanet_data
	{
		uint16_t flags;
#define YANET_UPDATE 0x0001 /* UPDATE or EoR */
#define YANET_ORIGIN 0x0004 /* has origin */
#define YANET_ASPATH 0x0008 /* has as-path */
#define YANET_NH 0x0010 /* has next-hop */
#define YANET_MED 0x0020 /* has multi-exit discriminator */
#define YANET_LPREF 0x0040 /* has local preference */
#define YANET_COMM 0x0080 /* has community */
#define YANET_LCOMM 0x0100 /* has large community */
#define YANET_LABELS 0x0200 /* has mpls labels */
		uint16_t safi;
		uint32_t afi;
		uint32_t med;
		uint32_t lpref;
		const char* next_hop;
		const char* origin;
		yanet_u32_t* as_path;
		yanet_u32_t* community;
		yanet_u32_t* lcommunity;
		yanet_u32_t* labels;
		const char* peer;
		list prefixes;
		list withdraw;
	} yanet_data_t;

	struct libyabird_t;

	struct libyabird_t* yanet_open(void);
	void yanet_close(struct libyabird_t* lh);
	void yanet_update(struct libyabird_t* lh, yanet_data_t* data);
	void yanet_set_state(struct libyabird_t* lh, const char* peer, int state);
#ifdef __cplusplus
};
#else /* __cplusplus */

// #define	YANET_DEBUG

#ifdef YANET_DEBUG
#include <cstdio>

extern int yanet_logfd;
#define BP(fmt, ...)                                              \
	do                                                        \
	{                                                         \
		if (yanet_logfd != -1)                            \
			dprintf(yanet_logfd, fmt, ##__VA_ARGS__); \
	} while (0)
#endif /* YANET_DEBUG */

extern struct libyabird_t* yanet;
#endif /* !__cplusplus */

#endif /* _LIBYABIRD_H_ */
