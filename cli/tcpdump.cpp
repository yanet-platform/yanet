#include <csignal>
#include <iostream>
#include <pcap/pcap.h>
#include <sys/shm.h>
#include <thread>

#include "common/idataplane.h"
#include "common/utils.h"
#include "dataplane/config.h"
#include "dataplane/pcap_dump_ring_meta.h"
#include "tcpdump.h"

namespace
{

using DumpRingDesc = tDataPlaneConfig::DumpRingDesc;
using DumpConfig = tDataPlaneConfig::DumpConfig;
using Meta = dumprings::PcapRingMeta;
using dumprings::GetSlotSize;
using dumprings::PcapHeader;
using utils::ShiftBuffer;

/* Stores information and state for a single shared memory ring being followed. */
struct RingView
{
	/* Pointer to the metadata in SHM. */
	Meta* meta;
	/* Pointer to the start of the packet data area in SHM. */
	std::byte* slots_ptr;
	/* Max size of ONE packet's data */
	size_t pkt_size;
	/* Total number of slots in the ring */
	size_t pkt_count;
	/* Total size of ONE slot (header + data + padding) */
	size_t slot_size;
	/* Absolute slot index of the next packet to read */
	uint64_t reader_pos;
	/* Identifier for this ring. */
	DumpRingDesc desc;

	RingView(Meta* meta_ptr,
	         std::byte* packets_ptr,
	         size_t packet_size,
	         size_t packet_count,
	         size_t total_slot_size,
	         uint64_t start_pos,
	         DumpRingDesc ring_desc) :
	        meta(meta_ptr),
	        slots_ptr(packets_ptr),
	        pkt_size(packet_size),
	        pkt_count(packet_count),
	        slot_size(total_slot_size),
	        reader_pos(start_pos),
	        desc(std::move(ring_desc))
	{}
};

std::atomic<bool> g_stop_flag{false};

void signal_handler_follow([[maybe_unused]] int sig)
{
	g_stop_flag.store(true, std::memory_order_relaxed);
	static int sigint_count = 0;
	sigint_count++;
	if (sigint_count > 1)
	{
		std::cerr << "\nForcing exit..." << std::endl;
		std::exit(EXIT_FAILURE);
	}
	std::cerr << "\nCtrl-C received, graceful shutdown initiated... "
	             "Press Ctrl-C again to force exit."
	          << std::endl;
}

void populate_out_rings(std::byte* ring_shm_start,
                        const DumpConfig& dump_config,
                        DumpRingDesc&& ring_desc,
                        std::vector<RingView>& out_rings)
{
	auto* ring_meta = reinterpret_cast<Meta*>(ring_shm_start);
	auto* slots_ptr = ShiftBuffer(ring_shm_start, sizeof(Meta));
	// The buffer has not yet been filled completely. Start from the beginning.
	uint64_t start_reader_pos = 0;

	uint64_t current_writer_pos = ring_meta->after.load(std::memory_order_acquire);
	if (current_writer_pos >= dump_config.count)
	{
		// The buffer has been lapped. The oldest valid packet is exactly one
		// buffer-length behind the writer's current position.
		start_reader_pos = current_writer_pos - dump_config.count;
	}

	out_rings.emplace_back(ring_meta,
	                       slots_ptr,
	                       dump_config.size, // TODO: not needed??
	                       dump_config.count,
	                       GetSlotSize(dump_config.size),
	                       start_reader_pos,
	                       std::move(ring_desc));
}

/**
 * @brief Attaches to shared memory segments and initializes RingView structures for matching rings.
 *
 * @param target_dump_tag The dump tag to filter rings by.
 * @param shm_info Vector of SHM information from the dataplane.
 * @param dataplane Reference to the dataplane interface.
 * @param out_rings Vector to populate with initialized RingView objects.
 * @param out_mapped_shm_base_ptrs Map to store base pointers of attached SHM segments for cleanup.
 *
 * @return True if at least one ring was successfully initialized, false otherwise.
 */
bool initialize_shm_rings(
        const std::string& target_dump_tag,
        const common::idp::get_shm_info::response& shm_info,
        interface::dataPlane& dataplane,
        std::vector<RingView>& out_rings,
        std::unordered_map<key_t, void*>& out_mapped_shm_base_ptrs)
{
	for (const auto& [ring_name, dump_tag, dump_config, core_id, socket_id, ipc_key, offset, capacity] : shm_info)
	{
		if (target_dump_tag != dump_tag)
		{
			continue;
		}

		if (dump_config.format != tDataPlaneConfig::DumpFormat::kPcap)
		{
			std::cerr << "Asked to tcpdump dump ring " << target_dump_tag
			          << ", but it is not configured to pcap format. "
			          << "Double-check dataplane.conf \"sharedMemory\" section" << std::endl;
			continue;
		}

		void* shm_base = nullptr;
		if (out_mapped_shm_base_ptrs.find(ipc_key) == out_mapped_shm_base_ptrs.end())
		{
			int shm_id = shmget(ipc_key, 0, 0);
			if (shm_id == -1)
			{
				std::cerr << "shmget failed for IPC key " << ipc_key
				          << " (ring '" << ring_name << "'): "
				          << strerror(errno) << ". Skipping." << std::endl;
				continue;
			}
			shm_base = shmat(shm_id, nullptr, 0);
			if (shm_base == reinterpret_cast<void*>(-1))
			{
				std::cerr << "shmat failed for IPC key " << ipc_key
				          << ", SHM ID " << shm_id
				          << " (ring '" << ring_name << "'): "
				          << strerror(errno) << ". Skipping." << std::endl;
				continue;
			}
			out_mapped_shm_base_ptrs[ipc_key] = shm_base;
		}
		else
		{
			shm_base = out_mapped_shm_base_ptrs[ipc_key];
		}

		auto* ring_shm_start = ShiftBuffer<std::byte*, void*>(shm_base, offset);
		DumpRingDesc desc{dump_tag, core_id, socket_id};
		populate_out_rings(ring_shm_start, dump_config, std::move(desc), out_rings);
	}

	return !out_rings.empty();
}

/**
 * @brief Processes available packets from a single ring using the slot-based model.
 */
bool process_ring_packets(RingView& ring,
                          bool& stdout_bad,
                          size_t& packets_written_this_loop,
                          size_t& bytes_written)
{
	uint64_t writer_pos = ring.meta->after.load(std::memory_order_acquire);

	if (ring.reader_pos >= writer_pos)
	{
		// No new packets to read.
		return false;
	}

	uint64_t slots_available = writer_pos - ring.reader_pos;
	// Lapped while running! This can happen multiple times between reads.
	// The number of packets completely lost to overwrites is at least
	// the number of new packets minus the buffer's capacity.
	if (slots_available > ring.pkt_count)
	{
		// The only safe action is to jump forward to the start of the
		// oldest valid slot, which is exactly one buffer-length behind the writer.
		ring.reader_pos = writer_pos - ring.pkt_count;
	}

	bool data_was_written = false;
	while (ring.reader_pos < writer_pos && !stdout_bad)
	{
		const size_t slot_idx = ring.reader_pos % ring.pkt_count;
		const std::byte* slot_ptr = ShiftBuffer(ring.slots_ptr, slot_idx * ring.slot_size);

		const auto* record_hdr = reinterpret_cast<const PcapHeader*>(slot_ptr);
		const size_t record_len = sizeof(PcapHeader) + record_hdr->incl_len;

		// Write the record (header + data) directly from the SHM slot to stdout.
		// This is safe because each slot is an independent, consistent unit.
		size_t written = fwrite(slot_ptr, 1, record_len, stdout);
		if (written != record_len)
		{
			if (ferror(stdout))
			{
				std::cerr << "stdout is in an error state. Halting output." << std::endl;
				stdout_bad = true;
			}
			break; // Stop processing this ring on write error.
		}

		ring.reader_pos++; // Advance to the next slot index
		data_was_written = true;
		packets_written_this_loop++;
		bytes_written += record_len;
	}

	return data_was_written;
}

void set_signal_handler()
{
	struct sigaction sigint_action_setup = {};
	sigint_action_setup.sa_handler = signal_handler_follow;
	sigemptyset(&sigint_action_setup.sa_mask);
	sigint_action_setup.sa_flags = 0;
	if (sigaction(SIGINT, &sigint_action_setup, nullptr) == -1)
	{
		std::cerr << "Failed to set SIGINT handler: " << strerror(errno)
		          << ". Proceeding without graceful Ctrl-C." << std::endl;
	}
}
}

inline void tcpdump_follow(const std::string& target_dump_tag)
{
	interface::dataPlane dataplane;
	const auto& shm_info = dataplane.get_shm_info();
	std::vector<RingView> rings;
	std::unordered_map<key_t, void*> shm_segments;

	// Lambda for RAII-like cleanup of shared memory segments
	auto shm_cleanup_action = [&](void*) {
		for (auto const& [key, ptr] : shm_segments)
		{
			if (ptr && ptr != reinterpret_cast<void*>(-1) && shmdt(ptr) == -1)
				std::cerr << "shmdt failed for IPC key " << key
				          << " during cleanup: " << strerror(errno) << std::endl;
		}
		shm_segments.clear();
	};

	// Calls cleanup_shm automatically on exit
	std::unique_ptr<void, decltype(shm_cleanup_action)> cleanup_guard(nullptr, shm_cleanup_action);

	if (!initialize_shm_rings(target_dump_tag, shm_info, dataplane, rings, shm_segments))
	{
		std::cerr << "ERROR: No matching PCAP rings found for tag '"
		          << target_dump_tag << "' or failed to initialize any." << std::endl;
		return;
	}

	// Write the global pcap header. All rings for a given tag have the same config.
	const pcap_file_header& file_header = rings.front().meta->pcap_header;
	if (fwrite(&file_header, 1, sizeof(file_header), stdout) != sizeof(file_header))
	{
		std::cerr << "ERROR: Failed to write PCAP global header. Aborting." << std::endl;
		return;
	}
	fflush(stdout);

	set_signal_handler();

	size_t total_packets_written = 0;
	size_t total_bytes_written = 0;
	bool stdout_has_error = false;

	while (!g_stop_flag.load(std::memory_order_relaxed) && !stdout_has_error)
	{
		bool data_written_in_current_cycle = false;
		size_t packets_this_cycle = 0;
		size_t bytes_this_cycle = 0;

		for (auto& ring : rings)
		{
			if (stdout_has_error)
				break;

			if (process_ring_packets(ring, stdout_has_error, packets_this_cycle, bytes_this_cycle))
			{
				data_written_in_current_cycle = true;
			}
		}

		total_packets_written += packets_this_cycle;
		total_bytes_written += bytes_this_cycle;

		if (data_written_in_current_cycle)
		{
			if (fflush(stdout) != 0 && !stdout_has_error)
			{
				std::cerr << "ERROR: fflush(stdout) in main loop failed: "
				          << strerror(errno) << " (errno " << errno << ")." << std::endl;
				if (ferror(stdout)) // Double check stream error state
				{
					std::cerr << "ERROR: stdout is confirmed in an error state "
					             "after loop flush. Halting output."
					          << std::endl;
					stdout_has_error = true;
				}
			}
		}
		else
		{
			// No data from any ring in this cycle, and not stopping yet. Pause briefly.
			if (!g_stop_flag.load(std::memory_order_relaxed) && !stdout_has_error)
			{
				std::this_thread::sleep_for(std::chrono::microseconds(1));
			}
		}
	}

	std::cerr << "\nCapture "
	          << (g_stop_flag.load(std::memory_order_acquire) ? "stopped by user." : "terminated.")
	          << (stdout_has_error ? " Due to stdout error." : "")
	          << ". Final stats:" << std::endl;
	std::cerr << "  Total packets successfully written: " << total_packets_written << std::endl;
	std::cerr << "  Total bytes successfully written to stdout: " << total_bytes_written << std::endl;
}
