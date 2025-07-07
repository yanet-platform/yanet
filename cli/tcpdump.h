#include <csignal>
#include <iostream>
#include <pcap/pcap.h>
#include <sys/shm.h>
#include <thread>

#include "common/idataplane.h"
#include "common/utils.h"
#include "dataplane/config.h"
#include "dataplane/dump_rings_meta.h"

namespace
{

using DumpRingDesc = tDataPlaneConfig::DumpRingDesc;
using dumprings::PcapOnDiskRecordHeader;
using dumprings::RingMeta;
using utils::ShiftBuffer;

static void print_pcap_helper(const std::vector<std::string>& created_files)
{
	std::cout << "Created the following pcap files:\n";
	for (const auto& file : created_files)
	{
		std::cout << "  " << file << "\n";
	}

	if (created_files.size() <= 1)
	{
		return;
	}

	std::cout << "\nTo combine them into a single pcap file for convenience, you can use:\n"
	          << "  mergecap -w combined.pcap";
	for (const auto& file : created_files)
	{
		std::cout << " " << file;
	}
	std::cout << "\n";
}

/* Stores information and state for a single shared memory ring being followed. */
struct RingView
{
	/* Pointer to the metadata in SHM. */
	RingMeta* meta;
	/* Pointer to the start of the packet data area in SHM. */
	uint8_t* start;
	/* Size of the packet data area. */
	size_t size;
	/* Current absolute read offset in the conceptual data stream. */
	uint64_t reader_pos;
	/* Identifier for this ring. */
	DumpRingDesc desc;
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
	std::cerr << "\nCtrl-C received, graceful shutdown initiated... Press Ctrl-C again to force exit." << std::endl;
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
			std::cerr << "Asked to follow dump ring " << target_dump_tag
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

		auto* ring_shm_start = ShiftBuffer<uint8_t*>(shm_base, offset);
		auto* ring_meta = reinterpret_cast<RingMeta*>(ring_shm_start);

		if (capacity <= sizeof(RingMeta))
		{
			std::cerr << "Ring '" << ring_name << "' capacity " << capacity
			          << " is too small (must be > " << sizeof(RingMeta)
			          << "). Skipping." << std::endl;
			continue;
		}
		uint8_t* data_buf = ShiftBuffer(ring_shm_start, sizeof(RingMeta));
		size_t data_buf_size = capacity - sizeof(RingMeta);

		DumpRingDesc desc{dump_tag, core_id, socket_id};
		out_rings.push_back({ring_meta, data_buf, data_buf_size, 0, desc});

		dataplane.switchToFollowDumpRing(desc); // Notify writer
	}

	return !out_rings.empty();
}

/**
 * @brief Writes the global PCAP file header to stdout.
 *
 * We print pcap file header manually even though this can be easilly done with libpcap:
 * ```cpp
 *  pcap_t* pcap_handle = pcap_open_dead(DLT_EN10MB, 65535 );
 *  pcap_dumper_t* stdout_dumper = pcap_dump_open(pcap_handle_for_header, "-"); // "-" means stdout
 *  pcap_dump_flush(stdout_dumper);
 *  pcap_dump_close(stdout_dumper);
 * ```
 * But libpcap has a bug: pcap_dump_close() also closes associated stream,
 * which in our case is stdout. This was fixed in libpcap 1.10.4 but we have mostly 1.10.1,
 * so do it the manual way
 */
bool write_pcap_global_header()
{
	pcap_file_header header;
	header.magic = 0xa1b2c3d4; // Standard for microsecond timestamps, little-endian
	header.version_major = 2;
	header.version_minor = 4;
	header.thiszone = 0; // GMT
	header.sigfigs = 0; // Accuracy of timestamps
	header.snaplen = 65535;
	header.linktype = DLT_EN10MB;

	size_t bytes_written = fwrite(&header, 1, sizeof(header), stdout);
	if (bytes_written != sizeof(header))
	{
		std::cerr << "Failed to write pcap global header to stdout. Expected " << sizeof(header)
		          << ", wrote " << bytes_written
		          << ". Error: " << strerror(errno)
		          << " (errno " << errno << ")." << std::endl;
		return false;
	}
	if (fflush(stdout) != 0)
	{
		std::cerr << "fflush(stdout) after global header write failed: " << strerror(errno)
		          << " (errno " << errno << ")." << std::endl;
		return false;
	}
	return true;
}

/**
 * @brief Reads a PCAP record header from the ring buffer, handling potential wrap-around.
 *
 * @param ring The RingView to read from.
 * @param out_header Pointer to store the read header.
 *
 * @return True if a header was successfully read, false if not enough data.
 */
bool read_pcap_record_header(RingView& ring, PcapOnDiskRecordHeader* out_header)
{
	constexpr size_t header_size = sizeof(PcapOnDiskRecordHeader);
	uint64_t writer_pos = ring.meta->after.load(std::memory_order_acquire); // Re-check writer pos

	if ((writer_pos - ring.reader_pos) < header_size)
	{
		// Not enough data for a full header yet
		return false;
	}

	size_t offset = ring.reader_pos % ring.size;
	size_t remaining = ring.size - offset;

	if (header_size <= remaining)
	{
		memcpy(out_header, ShiftBuffer(ring.start, offset), header_size);
	}
	else
	{
		// Header wraps around the SHM buffer
		memcpy(out_header, ShiftBuffer(ring.start, offset), remaining);
		memcpy(ShiftBuffer(out_header, remaining), ring.start, header_size - remaining);
	}
	return true;
}

/**
 * @brief Writes a complete PCAP record (header + payload) from the ring buffer to stdout.
 *
 * @param ring The RingView containing the record data (reader_pos points to start of record).
 * @param record_len Total length of the on-disk record (header + captured payload).
 */
bool write_pcap_record_to_stdout(const RingView& ring, size_t record_len)
{
	size_t offset = ring.reader_pos % ring.size;
	size_t remaining = ring.size - offset;
	size_t bytes_written = 0;

	if (record_len <= remaining)
	{
		bytes_written += fwrite(ShiftBuffer(ring.start, offset), 1, record_len, stdout);
	}
	else
	{
		// Record wraps
		size_t first_part_len = remaining;
		if (first_part_len > 0)
		{
			// Ensure there's something to write in the first part
			bytes_written += fwrite(ShiftBuffer(ring.start, offset), 1, first_part_len, stdout);
		}

		if (bytes_written == first_part_len)
		{
			// If first part succeeded (or was zero length and succeeded)
			size_t second_part_len = record_len - first_part_len;
			if (second_part_len > 0)
			{
				// Ensure there's something to write in the second part
				bytes_written += fwrite(ring.start, 1, second_part_len, stdout);
			}
		}
	}

	if (bytes_written != record_len)
	{
		std::cerr << "Failed to write full pcap record to stdout. Expected " << record_len
		          << ", wrote " << bytes_written
		          << ". Error: " << strerror(errno)
		          << " (errno " << errno << ")." << std::endl;
		return false;
	}
	return true;
}

/**
 * @brief Processes available packets from a single ring.
 *
 * @param ring The RingView to process.
 * @param stdout_bad Flag indicating if an error occurred on stdout.
 * @param packets_written_this_loop Counter for packets written in current main loop iteration.
 * @param bytes_written Counter for bytes written in current main loop iteration.
 *
 * @return True if any data was written from this ring, false otherwise.
 */
bool process_ring_packets(RingView& ring, bool& stdout_bad, size_t& packets_written_this_loop, size_t& bytes_written)
{
	bool data_was_written = false;
	uint64_t writer_after_pos = ring.meta->after.load(std::memory_order_acquire);

	// Calculate how much data is theoretically available
	uint64_t data_available = writer_after_pos - ring.reader_pos;

	// If the amount of unread data exceeds the buffer's capacity, the writer has
	// lapped us. The data at our current reader_pos is overwritten and invalid.
	if (data_available > ring.size)
	{
		uint64_t bytes_lost = data_available - ring.size;

		std::cerr << "[Ring " << ring.desc.tag
		          << "] Reader is too slow and was lapped by the writer. "
		          << "Available data (" << data_available
		          << ") > buffer size (" << ring.size << "). "
		          << "Jumping forward and skipping " << bytes_lost
		          << " bytes to avoid corruption." << std::endl;

		// The only safe action is to jump our read pointer to the writer's current
		// position. This discards all the packets we missed.
		ring.reader_pos = writer_after_pos;

		return false;
	}

	while (ring.reader_pos < writer_after_pos && !stdout_bad)
	{
		PcapOnDiskRecordHeader record_hdr;
		// Not enough data for a header
		if (!read_pcap_record_header(ring, &record_hdr))
		{
			break;
		}

		const size_t record_len = sizeof(PcapOnDiskRecordHeader) + record_hdr.incl_len;
		// Not enough data for the full record as per header
		if ((writer_after_pos - ring.reader_pos) < record_len)
		{
			break;
		}

		if (!write_pcap_record_to_stdout(ring, record_len))
		{
			if (ferror(stdout))
			{
				std::cerr << "stdout is in an error state. Halting output." << std::endl;
				stdout_bad = true;
			}
			break;
		}

		ring.reader_pos += record_len;
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
		std::cerr << "Failed to set SIGINT handler: " << strerror(errno) << ". Proceeding without graceful Ctrl-C." << std::endl;
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
				std::cerr << "shmdt failed for IPC key " << key << " during cleanup: " << strerror(errno) << std::endl;
		}
		shm_segments.clear();
	};

	// Calls cleanup_shm automatically on exit
	std::unique_ptr<void, decltype(shm_cleanup_action)> cleanup_guard(nullptr, shm_cleanup_action);

	if (!initialize_shm_rings(target_dump_tag, shm_info, dataplane, rings, shm_segments))
	{
		std::cerr << "ERROR: No matching PCAP rings found for tag '" << target_dump_tag << "' or failed to initialize any." << std::endl;
		return;
	}

	if (!write_pcap_global_header())
	{
		std::cerr << "ERROR: Failed to write PCAP global header. Aborting." << std::endl;
		return;
	}

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
				std::cerr << "ERROR: fflush(stdout) in main loop failed: " << strerror(errno) << " (errno " << errno << ")." << std::endl;
				if (ferror(stdout)) // Double check stream error state
				{
					std::cerr << "ERROR: stdout is confirmed in an error state after loop flush. Halting output." << std::endl;
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

	for (const auto& ring : rings)
	{
		dataplane.followDoneDumpRing(ring.desc);
	}
}

/**
 * @brief Dumps packets from shared memory rings configured in pcap mode.
 *
 * This function scans all known shared memory rings, and if a ring's tag matches the
 * provided `target_dump_tag` and it is configured in pcap format, the function dumps
 * packets to disk using the dataplane interface.
 *
 * @note If `path` is not provided, files will be dumped to `/tmp/`.
 *
 * @param target_dump_tag The tag of the dump ring to search for.
 * @param path Optional output directory for pcap files.
 */
inline void tcpdump_read(const std::string& target_dump_tag, std::optional<std::string> path)
{
	interface::dataPlane dataplane;
	const auto& shm_info = dataplane.get_shm_info();
	bool first_ring = true;
	std::vector<std::string> created_files;

	for (const auto& [ring_name, dump_tag, dump_config, core_id, socket_id, ipc_key, offset, capacity] : shm_info)
	{
		if (target_dump_tag != dump_tag)
			continue;

		if (dump_config.format != tDataPlaneConfig::DumpFormat::kPcap)
		{
			std::cerr << "ERROR: Asked to dump pcap files for dump tag " << target_dump_tag << ", but provided "
			          << "ring is not configured to pcap format. "
			          << "Double-check dataplane.conf \"sharedMemory\" section\n";
			return;
		}

		auto files = dataplane.tcpdump({dump_tag, core_id, socket_id, ring_name, path.value_or("/tmp/")});
		created_files.insert(created_files.end(), files.begin(), files.end());

		first_ring = false;
	}

	if (first_ring)
	{
		std::cerr << "ERROR: Asked to dump pcap files for dump ring " << target_dump_tag << ", but such ring was not found\n";
	}

	if (created_files.empty())
	{
		std::cout << "No pcap files were created. "
		             "Please check yanet-dataplane logs for more details.\n";
		return;
	}

	print_pcap_helper(created_files);
}
