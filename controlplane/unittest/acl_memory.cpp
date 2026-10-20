#include <atomic>
#include <cstdlib>
#include <new>

#include <gtest/gtest.h>

#include "controlplane/acl/rule.h"

namespace acl
{
uint8_t string_to_proto(const std::string& string);
}

namespace
{

std::atomic<size_t> allocations{0};
std::atomic<size_t> fail_at{0};
std::atomic<long> live{0};

void* allocate(std::size_t size)
{
	if (++allocations == fail_at)
	{
		throw std::bad_alloc();
	}
	void* memory = std::malloc(size ? size : 1);
	if (!memory)
	{
		throw std::bad_alloc();
	}
	++live;
	return memory;
}

void release(void* memory) noexcept
{
	if (memory)
	{
		--live;
		std::free(memory);
	}
}

}

void* operator new(std::size_t size) { return allocate(size); }
void* operator new[](std::size_t size) { return allocate(size); }
void operator delete(void* memory) noexcept { release(memory); }
void operator delete[](void* memory) noexcept { release(memory); }
void operator delete(void* memory, std::size_t) noexcept { release(memory); }
void operator delete[](void* memory, std::size_t) noexcept { release(memory); }

namespace
{

// Fails each allocation of the operation in turn and counts the failures that leak.
template<typename operation_t>
size_t leaks_on_failure(const operation_t& operation)
{
	operation();
	const size_t start = allocations;
	operation();
	const size_t count = allocations - start;

	size_t leaks = 0;
	for (size_t position = 1; position <= count; ++position)
	{
		const long before = live;
		fail_at = allocations + position;
		try
		{
			operation();
		}
		catch (const std::bad_alloc&)
		{
		}
		fail_at = 0;
		leaks += live != before;
	}
	return leaks;
}

constexpr const char* firewall = R"IPFW(
table _TARGETS_ create type iface
table _TARGETS_ add port0 :NEXT
add 10 skipto tablearg ip from any to any via table(_TARGETS_) in
add 20 deny ip from any to any in
:NEXT
add 30 allow tcp from 10.0.0.0/24 to any dst-port 80,443 in
add 40 allow icmp from any to any icmptypes 0,8 in
add 50 deny ip from any to any in
)IPFW";

TEST(ACLMemory, UnwindDoesNotLeakOnAllocationFailure)
{
	controlplane::base::acl_t config;
	config.aclId = 1;
	config.firewall = std::make_shared<ipfw::fw_config_t>(2);
	config.firewall->schedule_string(firewall);
	ASSERT_TRUE(config.firewall->parse() && config.firewall->validate());
	const controlplane::base::acl_rule_network_ipv4_t networks({common::ipv4_prefix_t("10.0.0.0/24")}, {common::ipv4_prefix_t("192.0.2.0/24")});
	config.nextModuleRules.emplace_back(networks, common::globalBase::tFlow(common::globalBase::eFlowType::route));

	const std::map<std::string, controlplane::base::acl_t> acls{{"acl0", config}};
	const acl::iface_map_t ifaces{{1, {{true, "port0"}, {false, "port0"}}}};
	const auto unwind = [&] {
		acl::result_t result;
		return acl::unwind_used_rules(acls, ifaces, nullptr, result);
	};

	EXPECT_EQ(leaks_on_failure(unwind), 0u);
}

TEST(ACLMemory, NumericProtocolIsNotCached)
{
	acl::string_to_proto("tcp");
	const size_t start = allocations;
	acl::string_to_proto("0x6");
	EXPECT_EQ(allocations.load(), start);
}

}
