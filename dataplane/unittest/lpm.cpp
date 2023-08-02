//! In this LPM insertion order matters!

#include <cctype>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "../src/lpm.h"

namespace
{

/// Non-functional extension of an LPM to provide nice dump methods.
template<uint32_t TExtendedSize>
class lpm6_8x16bit_atomic : public dataplane::lpm6_8x16bit_atomic<TExtendedSize>
{
public:
	void print() const
	{
		auto envPtr = std::getenv("YANET_TEST_DEBUG");
		if (envPtr == nullptr)
		{
			return;
		}

		std::string env(envPtr);
		if (env == "plain")
		{
			print_table();
			return;
		}
		if (env == "graph")
		{
			print_digraph();
			return;
		}
	}

	void print_table() const
	{
		printf("==================================\n");
		print_chunk(this->rootChunk, -1, true);
		for (unsigned int j = 0; j < TExtendedSize; j++)
		{
			print_chunk(this->extendedChunks[j], j);
		}
	}

	void print_digraph() const
	{
		printf("%s\n", digraph().data());
	}

	std::string digraph() const
	{
		std::ostringstream s;
		s << "digraph G {\n";
		s << "  nodesep=.05;\n";
		s << "  rankdir=LR;\n";
		s << "  node [shape=record fontname=\"Monospace\" fontsize=10];\n";
		s << "  node [width = 0.5];\n";
		build_digraph_chunk(this->rootChunk, "R", s, true);
		for (unsigned int j = 0; j < TExtendedSize; j++)
		{
			build_digraph_chunk(this->extendedChunks[j], j, s);
		}
		s << "}\n";

		return s.str();
	}

private:
	struct entry_t
	{
		int from;
		int to;
		uint32_t flags;
		uint32_t value;
	};

	template<typename T, typename F>
	void visit_chunk(const T& chunk, bool isRoot, const F& fn) const
	{
		if (!(chunk.entries[0].flags & this->flagExtendedChunkOccupied) && !isRoot)
		{
			return;
		}

		int minDupIdx = 0;
		for (int i = 1; i < 256 * 256; i++)
		{
			auto currEntry = chunk.entries[i];
			currEntry.flags &= ~(this->flagExtendedChunkOccupied);
			auto prevEntry = chunk.entries[i - 1];
			prevEntry.flags &= ~(this->flagExtendedChunkOccupied);
			auto minDupIdxEntry = chunk.entries[minDupIdx];
			minDupIdxEntry.flags &= ~(this->flagExtendedChunkOccupied);

			if (currEntry.atomic != prevEntry.atomic)
			{
				if (minDupIdxEntry.atomic != 0)
				{
					fn(entry_t{minDupIdx, i - 1, minDupIdxEntry.flags, minDupIdxEntry.valueId});
				}
				minDupIdx = i;
			}
		}
		if (chunk.entries[minDupIdx].atomic != 0)
		{
			fn(entry_t{minDupIdx, 0xffff, chunk.entries[minDupIdx].flags, chunk.entries[minDupIdx].valueId});
		}
	}

	template<typename T>
	void print_chunk(const T& chunk, int chunkId, bool isRoot = false) const
	{
		visit_chunk(chunk, isRoot, [&](entry_t entry) {
			if (entry.from == entry.to)
			{
				printf("%2d %04x      : flags=0x%02x, value=%d\n", chunkId, entry.from, entry.flags, entry.value);
			}
			else
			{
				printf("%2d %04x..%04x: flags=0x%02x, value=%d\n", chunkId, entry.from, entry.to, entry.flags, entry.value);
			}
		});
	}

	template<typename T, typename N>
	void build_digraph_chunk(const T& chunk, N j, std::ostringstream& s, bool isRoot = false) const
	{
		std::vector<entry_t> entries;
		visit_chunk(chunk, isRoot, [&](entry_t entry) {
			entries.push_back(entry);
		});

		if (!entries.empty())
		{
			s << "  node" << j << "[label=\"<n>[" << j << "]|{{";
			for (auto p = entries.begin(); p != entries.end(); ++p)
			{
				if (p->from == p->to)
				{
					char buf[16] = {};
					std::snprintf(buf, 8, "%04x", p->from);
					s << buf;
				}
				else
				{
					char buf[16] = {};
					std::snprintf(buf, 12, "%04x-%04x", p->from, p->to);
					s << buf;
				}
				if (p != entries.end() - 1)
				{
					s << "|";
				}
			}
			s << "}|{";
			for (unsigned int i = 0; i < entries.size(); ++i)
			{
				s << "<f" << i << ">";
				if (entries[i].flags & this->flagValid)
				{
					s << entries[i].value;
				}
				if (i != entries.size() - 1)
				{
					s << "|";
				}
			}
			s << "}}\"];\n";

			for (unsigned int i = 0; i < entries.size(); ++i)
			{
				if (entries[i].flags & this->flagExtended)
				{
					s << "  node" << j << ":f" << i << "->node" << entries[i].value << ":n\n";
				}
			}
		}
	}
};

TEST(LPM, Lookup)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	uint32_t valueId{0};
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::1"), &valueId));

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234::"), 64, 4299));

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::1"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:ffff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);

	t->print();
}

TEST(LPM, LookupUnalignedBitMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234::"), 69, 4299));

	uint32_t valueId{0};
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:07ff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);

	// Out of range.
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:800:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(dataplane::lpmValueIdInvalid, valueId);

	t->print();
}

TEST(LPM, LookupOverlapped)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234::"), 64, 4299));
	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234:4800::"), 69, 589));

	uint32_t valueId{0};
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:47ff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:4800::"), &valueId));
	EXPECT_EQ(589, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:4fff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(589, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:5000:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:ffff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);

	t->print();
}

TEST(LPM, LookupOverlappedSimple)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	const std::vector<std::tuple<std::string, uint8_t, uint32_t>> entries{
	    {"::", 0, 1},
	    {"10:20::", 32, 2},
	};

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t(net), mask, value));
	}

	uint32_t valueId{0};

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("::1"), &valueId));
	EXPECT_EQ(1, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("10:20::1"), &valueId));
	EXPECT_EQ(2, valueId);

	t->print();
}

TEST(LPM, LookupExtMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	uint32_t valueId{0};
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::1"), &valueId));

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234::"), common::ipv6_address_t("ffff:ffff:ffff:ffff::"), 4299));

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::1"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:ffff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);

	t->print();
}

TEST(LPM, LookupUnalignedBitExtMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234::"), common::ipv6_address_t("ffff:ffff:ffff:ffff:f800::"), 4299));

	uint32_t valueId{0};
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:07ff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);

	// Out of range.
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:800:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(dataplane::lpmValueIdInvalid, valueId);

	t->print();
}

TEST(LPM, LookupOverlappedExt)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	const std::vector<std::tuple<std::string, std::string, uint32_t>> entries{
	    {"2222:777:aabc:1234::", "ffff:ffff:ffff:ffff::", 4299},
	    {"2222:777:aabc:1234:4800::", "ffff:ffff:ffff:ffff:f800::", 589},
	};

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(t->insert(common::ipv6_address_t(net), common::ipv6_address_t(mask), value), eResult::success);
		t->print();
	}

	uint32_t valueId{0};

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:47ff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:4800::"), &valueId));
	EXPECT_EQ(589, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:4fff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(589, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:5000::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:ffff:ffff:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);

	t->print();
}

TEST(LPM, LookupProjectIDExtMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<128>>();

	uint32_t valueId{0};
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:0:1234:0:1"), &valueId));

	// 1234@2222:777:aabc::/48
	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc::1234:0:0"), common::ipv6_address_t("ffff:ffff:ffff:0:ffff:ffff::"), 4299));

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:0:1234:0:1"), &valueId));
	EXPECT_EQ(4299, valueId);

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:0:1234::"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:0:1234:ffff:ffff"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("2222:777:aabc:1234:0:1233::"), &valueId));
	EXPECT_EQ(dataplane::lpmValueIdInvalid, valueId);

	t->print();
}

TEST(LPM, LookupManyProjectIDsExtMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	const std::vector<std::tuple<std::string, std::string, uint32_t>> entries{
	    {"2222:777:aabc::1234:0:0", "ffff:ffff:ffff:0:ffff:ffff::", 100},
	    {"2222:777:aabc::1122:0:0", "ffff:ffff:ffff:0:ffff:ffff::", 101},
	    {"2222:777:ff1d::", "ffff:ffff:ffff::", 102},
	    {"2222:777:c00:0:add:8765::", "ffff:ffff:ff00:0:ffff:ffff::", 103},
	    {"2222:777:c00:0:add:8005::", "ffff:ffff:ff00:0:ffff:ffff::", 104},
	    {"2222:770:c00::f800:0:0", "ffff:ffff:ff00:0:ffff:f800::", 105},
	};

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(t->insert(common::ipv6_address_t(net), common::ipv6_address_t(mask), value), eResult::success);
	}

	const std::vector<std::tuple<std::string, uint32_t>> cases{
	    /// Value 100
	    {"2222:777:aabc:1234:0:1234::", 100},
	    {"2222:777:aabc:1234:0:1234:0:1", 100},
	    {"2222:777:aabc:1234:0:1234::", 100},
	    {"2222:777:aabc:1234:0:1234:0:ffff", 100},
	    {"2222:777:aabc:1234:0:1234:ffff:ffff", 100},

	    /// Value 101
	    {"2222:777:aabc::1122:0:0", 101},
	    {"2222:777:aabc::1122:0:1", 101},
	    {"2222:777:aabc:ff00:0:1122:0:1", 101},
	    {"2222:777:aabc:ffff:0:1122:0:1", 101},

	    /// Value 102
	    {"2222:777:ff1d::1", 102},
	    {"2222:777:ff1d:ff00::1", 102},
	    {"2222:777:ff1d:ff00:0:1234:0:1", 102},

	    /// Value 103
	    {"2222:777:c00:0:add:8765::", 103},
	    {"2222:777:c00:0:add:8765:0:1", 103},
	    {"2222:777:c00:0:add:8765:0:2211", 103},
	    {"2222:777:c00:0:add:8765:4433:0", 103},
	    {"2222:777:c77:6655:add:8765:4433:2211", 103},

	    /// Value 104
	    {"2222:777:c00:0:add:8005::", 104},
	    {"2222:777:c00:0:add:8005:0:1", 104},
	    {"2222:777:c00:0:add:8005:0:2211", 104},
	    {"2222:777:c00:0:add:8005:4433:0", 104},
	    {"2222:777:c77:6655:add:8005:4433:2211", 104},

	    /// Value 105
	    {"2222:770:c00::f800:0:0", 105},
	    {"2222:770:c00::f800:0:11", 105},
	    {"2222:770:c00::f800:4433:2211", 105},
	    {"2222:770:c00::f900:4433:2211", 105},
	    {"2222:770:c00::ff00:4433:2211", 105},
	    {"2222:770:c00::ff01:4433:2211", 105},
	    {"2222:770:c00::fffe:4433:2211", 105},
	    {"2222:770:c00::ffff:4433:2211", 105},
	    {"2222:770:c00:8877:0:ffff:4433:2211", 105},
	    {"2222:770:c99:8877:0:ffff:4433:2211", 105},

	    /// Invalid
	    {"2222:777:aabc::1134:0:1", dataplane::lpmValueIdInvalid},
	    {"2222:777:ff1f::1234:0:1", dataplane::lpmValueIdInvalid},
	    {"2222:770:c00::f7ff:4433:2211", dataplane::lpmValueIdInvalid},
	};

	for (auto [addr, value] : cases)
	{
		uint32_t valueId{0};
		EXPECT_EQ(value != dataplane::lpmValueIdInvalid, t->lookup(common::ipv6_address_t(addr), &valueId));
		EXPECT_EQ(value, valueId);
	}

	t->print();
}

TEST(LPM, LookupTrouble)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	const std::vector<std::tuple<std::string, std::string, uint32_t>> entries{
	    {"2222:777:aabc:2030::", "ffff:ffff:ffff:fff0::", 589},
	    {"2222:777:aabc:2030::", "ffff:ffff:ffff:ffff::", 42},
	    {"2222:777:aabc:2030:0:1234::", "ffff:ffff:ffff:fff0:ffff:ffff::", 4299},
	    {"2222:777:aabc:2030:0:5678::", "ffff:ffff:ffff:fff0:ffff:ffff::", 4298},
	    {"2222:777:aabc:2030:aabb:5678::", "ffff:ffff:ffff:fff0:ffff:ffff::", 4297},
	};

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(t->insert(common::ipv6_address_t(net), common::ipv6_address_t(mask), value), eResult::success);
		t->print();
	}

	const std::vector<std::tuple<std::string, uint32_t>> cases{
	    {"2222:777:aabc:2030::1", 42},
	    {"2222:777:aabc:2030:0:0:ffff:1", 42},
	    {"2222:777:aabc:2030:0:ffff:0:1", 42},
	    {"2222:777:aabc:2030:0:ffff:ffff:1", 42},
	    {"2222:777:aabc:2030:aabb:ffff:ffff:1", 42},

	    {"2222:777:aabc:2031::1", 589},
	    {"2222:777:aabc:2032::1", 589},
	    {"2222:777:aabc:2033::1", 589},
	    {"2222:777:aabc:2034::1", 589},
	    {"2222:777:aabc:2035::1", 589},
	    {"2222:777:aabc:2036::1", 589},
	    {"2222:777:aabc:2037::1", 589},
	    {"2222:777:aabc:2038::1", 589},
	    {"2222:777:aabc:2039::1", 589},
	    {"2222:777:aabc:203a::1", 589},
	    {"2222:777:aabc:203b::1", 589},
	    {"2222:777:aabc:203c::1", 589},
	    {"2222:777:aabc:203d::1", 589},
	    {"2222:777:aabc:203e::1", 589},
	    {"2222:777:aabc:203f::1", 589},
	    {"2222:777:aabc:2031:0:0:ffff:1", 589},
	    {"2222:777:aabc:2032:0:ffff:0:1", 589},
	    {"2222:777:aabc:2033:0:ffff:ffff:1", 589},
	    {"2222:777:aabc:2034:aabb:ffff:ffff:1", 589},

	    {"2222:777:aabc:2030:0:1234:0:1", 4299},
	    {"2222:777:aabc:2031:0:1234:0:1", 4299},
	    {"2222:777:aabc:2032:0:1234:0:1", 4299},
	    {"2222:777:aabc:2033:0:1234:0:1", 4299},
	    {"2222:777:aabc:2034:0:1234:0:1", 4299},
	    {"2222:777:aabc:2035:0:1234:0:1", 4299},
	    {"2222:777:aabc:2036:0:1234:0:1", 4299},
	    {"2222:777:aabc:2037:0:1234:0:1", 4299},
	    {"2222:777:aabc:2038:0:1234:0:1", 4299},
	    {"2222:777:aabc:2039:0:1234:0:1", 4299},
	    {"2222:777:aabc:203a:0:1234:0:1", 4299},
	    {"2222:777:aabc:203b:0:1234:0:1", 4299},
	    {"2222:777:aabc:203c:0:1234:0:1", 4299},
	    {"2222:777:aabc:203d:0:1234:0:1", 4299},
	    {"2222:777:aabc:203e:0:1234:0:1", 4299},
	    {"2222:777:aabc:203f:0:1234:0:1", 4299},

	    {"2222:777:aabc:2030:0:5678:0:1", 4298},
	    {"2222:777:aabc:2031:0:5678:0:1", 4298},
	    {"2222:777:aabc:2032:0:5678:0:1", 4298},
	    {"2222:777:aabc:2033:0:5678:0:1", 4298},
	    {"2222:777:aabc:2034:0:5678:0:1", 4298},
	    {"2222:777:aabc:2035:0:5678:0:1", 4298},
	    {"2222:777:aabc:2036:0:5678:0:1", 4298},
	    {"2222:777:aabc:2037:0:5678:0:1", 4298},
	    {"2222:777:aabc:2038:0:5678:0:1", 4298},
	    {"2222:777:aabc:2039:0:5678:0:1", 4298},
	    {"2222:777:aabc:203a:0:5678:0:1", 4298},
	    {"2222:777:aabc:203b:0:5678:0:1", 4298},
	    {"2222:777:aabc:203c:0:5678:0:1", 4298},
	    {"2222:777:aabc:203d:0:5678:0:1", 4298},
	    {"2222:777:aabc:203e:0:5678:0:1", 4298},
	    {"2222:777:aabc:203f:0:5678:0:1", 4298},

	    {"2222:777:aabc:2030:aabb:5678::1", 4297},
	    {"2222:777:aabc:2031:aabb:5678::1", 4297},
	    {"2222:777:aabc:2032:aabb:5678::1", 4297},
	    {"2222:777:aabc:2033:aabb:5678::1", 4297},
	    {"2222:777:aabc:2034:aabb:5678::1", 4297},
	    {"2222:777:aabc:2035:aabb:5678::1", 4297},
	    {"2222:777:aabc:2036:aabb:5678::1", 4297},
	    {"2222:777:aabc:2037:aabb:5678::1", 4297},
	    {"2222:777:aabc:2038:aabb:5678::1", 4297},
	    {"2222:777:aabc:2039:aabb:5678::1", 4297},
	    {"2222:777:aabc:203a:aabb:5678::1", 4297},
	    {"2222:777:aabc:203b:aabb:5678::1", 4297},
	    {"2222:777:aabc:203c:aabb:5678::1", 4297},
	    {"2222:777:aabc:203d:aabb:5678::1", 4297},
	    {"2222:777:aabc:203e:aabb:5678::1", 4297},
	    {"2222:777:aabc:203f:aabb:5678::1", 4297},
	};

	for (auto [addr, value] : cases)
	{
		uint32_t valueId{0};
		EXPECT_EQ(value != dataplane::lpmValueIdInvalid, t->lookup(common::ipv6_address_t(addr), &valueId));
		EXPECT_EQ(value, valueId) << common::ipv6_address_t(addr).toString() << " -> " << value;
	}

	t->print();
}

TEST(LPM, LookupMixedNetworksWithSamePrefix)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	const std::vector<std::tuple<std::string, std::string, uint32_t>> entries{
	    {"2222:777:c00::", "ffff:ffff:ff00::", 589},
	    {"2222:777:c00:0:add:8765::", "ffff:ffff:ff00:0:ffff:ffff::", 4299},
	};

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(t->insert(common::ipv6_address_t(net), common::ipv6_address_t(mask), value), eResult::success);
	}

	const std::vector<std::tuple<std::string, uint32_t>> cases{
	    {"2222:777:c00:0:add:8765:0:1", 4299},
	    {"2222:777:c00:0:10d:4d60:0:1", 589},
	};

	for (auto [addr, value] : cases)
	{
		uint32_t valueId{0};
		EXPECT_EQ(value != dataplane::lpmValueIdInvalid, t->lookup(common::ipv6_address_t(addr), &valueId));
		EXPECT_EQ(value, valueId);
	}

	t->print();
}

TEST(LPM, LookupSummary)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	const std::vector<std::tuple<std::string, std::string, uint32_t>> entries{
	    {"::", "::", 1001},
	    {"1111:2222::", "ffff:ffff::", 1002},
	    {"3333:4444:5555::", "ffff:ffff:ffff::", 1003},
	    {"3333:4444:5555:0:aaaa:bbbb::", "ffff:ffff:ffff:0:ffff:ffff::", 1004},
	    {"3333:4444:5555:6666::", "ffff:ffff:ffff:ffff::", 1005},
	    {"3333:4444:5555:6666:aaaa:bbbb::", "ffff:ffff:ffff:ffff:ffff:ffff::", 1006},
	    {"3333:4444:5555:6666:aaaa:bbbb:cccc:dddd", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1007},
	};

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t(net), common::ipv6_address_t(mask), value));
		t->print();
	}

	const std::vector<std::tuple<std::string, uint32_t>> cases{
	    {"::1", 1001},
	    {"1111:2222:c00::1", 1002},
	    {"3333:4444:5555::1", 1003},
	    {"3333:4444:5555:0:aaaa:bbbb:0:1", 1004},
	    {"3333:4444:5555:1:aaaa:bbbb:0:1", 1004},
	    {"3333:4444:5555:ffff:aaaa:bbbb:0:1", 1004},
	    {"3333:4444:5555:6666::1", 1005},
	    {"3333:4444:5555:6666:aaaa::1", 1005},
	    {"3333:4444:5555:6666:0:bbbb:0:1", 1005},
	    {"3333:4444:5555:6666:aaaa:bbbb:0:1", 1006},
	    {"3333:4444:5555:6666:aaaa:bbbb:cccc:dddd", 1007},
	};

	for (auto [addr, value] : cases)
	{
		uint32_t valueId{0};
		EXPECT_EQ(value != dataplane::lpmValueIdInvalid, t->lookup(common::ipv6_address_t(addr), &valueId));
		EXPECT_EQ(value, valueId);
	}

	t->print();
}

TEST(LPM, LookupMerge)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	for (int i = 65535; i >= 1; i--)
	{
		std::array<uint8_t, 16> addr{0x11, 0x11, 0x22, 0x22, uint8_t(i / 256), uint8_t(i % 256), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t(addr), common::ipv6_address_t("ffff:ffff:ffff::"), 1000));
	}

	EXPECT_EQ(2, t->getStats().extendedChunksCount);

	std::array<uint8_t, 16> addr{0x11, 0x11, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t(addr), common::ipv6_address_t("ffff:ffff:ffff::"), 1000));
	EXPECT_EQ(1, t->getStats().extendedChunksCount);

	t->print();
}

TEST(LPM, LookupCruelRealWorld)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<512>>();

	std::ifstream stream("networks.txt");
	std::string line;
	int counter = 1000000; // Easier to match by eyes.
	std::vector<std::tuple<std::string, std::string, uint32_t>> entries;
	while (std::getline(stream, line))
	{
		auto pos = line.find('/');
		auto addr = line.substr(0, pos);
		auto mask = line.substr(pos + 1);
		if (pos == std::string::npos)
		{
			mask = "128";
		}

		auto isNumber = !mask.empty() && std::all_of(mask.begin(), mask.end(), ::isdigit);
		if (isNumber)
		{
			// Nevermind. The easiest way to convert ones set to proper IPv6 address.
			mask = common::ipv6_address_t(t->createMask(std::stoi(mask, nullptr, 10))).toString();
		}
		entries.emplace_back(addr, mask, counter++);
	}

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t(net), common::ipv6_address_t(mask), value))
		    << "Failed to insert " << value;
	}

	t->print();
}

TEST(LPM, RemoveOne)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234::"), 64, 4299));
	EXPECT_EQ(3, t->getStats().extendedChunksCount);

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("2222:777:aabc:1234::"), 64));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	t->print();
}

TEST(LPM, RemoveNotSame)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("::"), 0, 4299));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("::1"), 128));
	EXPECT_EQ(7, t->getStats().extendedChunksCount);

	uint32_t valueId{0};
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("::1"), &valueId));
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("::2"), &valueId));
	EXPECT_EQ(4299, valueId);

	t->print();
}

TEST(LPM, RemoveNet)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("1111:2222::"), 32, 100));
	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("1111:2222:3333::"), 48, 101));
	EXPECT_EQ(2, t->getStats().extendedChunksCount);

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("1111:2222::"), 32));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	t->print();
}

TEST(LPM, RemoveOneWithMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("2222:777:aabc:1234::"), common::ipv6_address_t("ffff:ffff:ffff:ffff::"), 4299));
	EXPECT_EQ(3, t->getStats().extendedChunksCount);

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("2222:777:aabc:1234::"), common::ipv6_address_t("ffff:ffff:ffff:ffff::")));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	t->print();
}

TEST(LPM, RemoveNotSameWithMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("::"), common::ipv6_address_t("::"), 4299));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("::1"), common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
	EXPECT_EQ(7, t->getStats().extendedChunksCount);

	uint32_t valueId{0};
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("::1"), &valueId));
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("::2"), &valueId));
	EXPECT_EQ(4299, valueId);

	t->print();
}

TEST(LPM, RemoveNetWithMask)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("1111:2222::"), common::ipv6_address_t("ffff:ffff::"), 100));
	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("1111:2222:3333::"), common::ipv6_address_t("ffff:ffff:ffff::"), 101));
	EXPECT_EQ(2, t->getStats().extendedChunksCount);

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("1111:2222::"), common::ipv6_address_t("ffff:ffff::")));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	t->print();
}

TEST(LPM, RemoveGappedNetwork)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t("::"), common::ipv6_address_t("::"), 4299));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("1111:2222:0:0:aaaa:bbbb::"), common::ipv6_address_t("ffff:ffff:0:0:ffff:ffff:0:0")));
	EXPECT_EQ(5, t->getStats().extendedChunksCount);

	uint32_t valueId{0};
	EXPECT_FALSE(t->lookup(common::ipv6_address_t("1111:2222:3333:4444:aaaa:bbbb::1"), &valueId));
	EXPECT_EQ(dataplane::lpmValueIdInvalid, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("1111:2222:3333:4444:aaaa:cccc::2"), &valueId));
	EXPECT_EQ(4299, valueId);

	t->print();
}

TEST(LPM, LookupSummaryWithClear)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	const std::vector<std::tuple<std::string, std::string, uint32_t>> entries{
	    {"::", "::", 1001},
	    {"1111:2222::", "ffff:ffff::", 1002},
	    {"3333:4444:5555::", "ffff:ffff:ffff::", 1003},
	    {"3333:4444:5555:0:aaaa:bbbb::", "ffff:ffff:ffff:0:ffff:ffff::", 1004},
	    {"3333:4444:5555:6666::", "ffff:ffff:ffff:ffff::", 1005},
	    {"3333:4444:5555:6666:aaaa:bbbb::", "ffff:ffff:ffff:ffff:ffff:ffff::", 1006},
	};

	for (auto [net, mask, value] : entries)
	{
		EXPECT_EQ(eResult::success, t->insert(common::ipv6_address_t(net), common::ipv6_address_t(mask), value));
	}

	EXPECT_EQ(eResult::success, t->remove(common::ipv6_address_t("::"), common::ipv6_address_t("::")));
	EXPECT_EQ(0, t->getStats().extendedChunksCount);

	t->print();
}

TEST(LPM, InsertCorruption)
{
	auto t = std::make_unique<lpm6_8x16bit_atomic<64>>();

	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777::00af"),
		  common::ipv6_address_t("ffff:ffff::ffff:ffff:ffff:ffff"), 4299));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:1a::a1"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 589));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:2a::a1"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 105));

	uint32_t valueId{0};
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:1a::a1"), &valueId));
	EXPECT_EQ(589, valueId);

	t->print();

	t->clear();
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777::00af"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 456));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:1a::00af"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 890));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:2a::00af"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 999));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777::00af"),
		  common::ipv6_address_t("ffff:ffff::ffff:ffff:ffff:ffff"), 4299));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:1a::a1"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 589));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:2a::a1"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 105));

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777::af"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:1a::a1"), &valueId));
	EXPECT_EQ(589, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:2a::a1"), &valueId));
	EXPECT_EQ(105, valueId);

	t->print();

	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:1a::a1"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 1112));
	EXPECT_EQ(eResult::success,
		  t->insert(common::ipv6_address_t("2222:777:2a::a1"),
		  common::ipv6_address_t("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 1221));

	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777::af"), &valueId));
	EXPECT_EQ(4299, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:1a::a1"), &valueId));
	EXPECT_EQ(1112, valueId);
	EXPECT_TRUE(t->lookup(common::ipv6_address_t("2222:777:2a::a1"), &valueId));
	EXPECT_EQ(1221, valueId);

	t->print();


}


} // namespace
