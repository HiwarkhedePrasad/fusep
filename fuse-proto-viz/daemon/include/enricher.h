// ═══════════════════════════════════════════════════════════════════════
//  enricher.h  —  Metadata Enrichment Engine
//
//  Resolves PIDs to process names, container IDs, and Kubernetes
//  metadata by reading /proc and container runtime APIs.
//  Caches results in an std::unordered_map.
// ═══════════════════════════════════════════════════════════════════════

#pragma once

#include "fuse_types.h"
#include "spsc_queue.h"
#include <thread>
#include <atomic>
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace fuseviz {

class Enricher {
public:
    Enricher() = default;

    // Start the enrichment worker thread
    void start(
        SPSCQueue<struct fuse_trace_event, 1 << 16>& input_queue,
        SPSCQueue<EnrichedEvent, 1 << 16>& output_queue,
        std::atomic<bool>& running
    );

    uint64_t dropped_count() const { return dropped_; }

private:
    std::atomic<uint64_t> dropped_{0};
    // Resolve process metadata for a PID
    struct ProcessInfo {
        std::string name;
        std::string container_id;
        std::string pod_name;
        std::string namespace_;
        std::chrono::steady_clock::time_point cached_at;
    };

    std::mutex cache_mutex_;
    std::unordered_map<uint32_t, ProcessInfo> cache_;
    static constexpr auto CACHE_TTL = std::chrono::seconds(30);

    const ProcessInfo& resolve(uint32_t pid);
    std::string read_proc_comm(uint32_t pid);
    std::string read_proc_cgroup(uint32_t pid);
    std::string extract_container_id(const std::string& cgroup_content);
};

} // namespace fuseviz
