// ═══════════════════════════════════════════════════════════════════════
//  enricher.cpp  —  Metadata Enrichment Engine Implementation
// ═══════════════════════════════════════════════════════════════════════

#include "enricher.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>

namespace fuseviz {

void Enricher::start(
    SPSCQueue<struct fuse_trace_event, 1 << 16>& input_queue,
    SPSCQueue<EnrichedEvent, 1 << 16>& output_queue,
    std::atomic<bool>& running)
{
    fprintf(stderr, "[Enricher] Worker thread started\n");

    while (running.load(std::memory_order_relaxed)) {
        auto raw = input_queue.pop();
        if (!raw.has_value()) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            continue;
        }

        const auto& evt = raw.value();

        EnrichedEvent enriched;
        enriched.raw = evt;
        enriched.opcode_name = OpcodeNames::get(evt.opcode);

        // Resolve process metadata
        const auto& info = resolve(evt.pid);
        enriched.process_name = info.name;
        enriched.container_id = info.container_id;
        enriched.pod_name = info.pod_name;
        enriched.namespace_ = info.namespace_;

        // Push to output queue (drop if full — prefer latency over backpressure)
        if (!output_queue.push(std::move(enriched))) {
            auto prev = dropped_.fetch_add(1, std::memory_order_relaxed);
            if (prev == 0 || prev % 100 == 0) {
                fprintf(stderr, "[Enricher] Warning: output queue full, dropped %llu events (total)\n",
                        prev + 1);
            }
        }
    }

    fprintf(stderr, "[Enricher] Worker thread stopped\n");
}

const Enricher::ProcessInfo& Enricher::resolve(uint32_t pid) {
    auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(pid);

    if (it != cache_.end()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.cached_at);
        if (age < CACHE_TTL) {
            return it->second;
        }
        // Cache expired — re-resolve
        cache_.erase(it);
    }

    // Resolve from /proc
    ProcessInfo info;
    info.name = read_proc_comm(pid);
    info.container_id = read_proc_cgroup(pid);
    info.cached_at = now;

    auto [inserted, _] = cache_.emplace(pid, std::move(info));
    return inserted->second;
}

std::string Enricher::read_proc_comm(uint32_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);

    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        return "pid:" + std::to_string(pid);
    }

    std::string comm;
    std::getline(ifs, comm);
    // Trim trailing newline
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) {
        comm.pop_back();
    }
    return comm;
}

std::string Enricher::read_proc_cgroup(uint32_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);

    std::ifstream ifs(path);
    if (!ifs.is_open()) return "";

    std::string line;
    while (std::getline(ifs, line)) {
        std::string cid = extract_container_id(line);
        if (!cid.empty()) return cid;
    }
    return "";
}

std::string Enricher::extract_container_id(const std::string& cgroup) {
    // Docker: /docker/<container_id>
    {
        auto pos = cgroup.find("/docker/");
        if (pos != std::string::npos) {
            auto start = pos + 8;
            auto end = cgroup.find('/', start);
            auto id = cgroup.substr(start, end == std::string::npos
                ? std::string::npos : end - start);
            if (id.length() >= 12) return id.substr(0, 12);
        }
    }

    // Kubernetes: /kubepods/.../<container_id>
    {
        auto pos = cgroup.find("/kubepods");
        if (pos != std::string::npos) {
            // Find the last segment that looks like a container ID
            size_t last_slash = cgroup.rfind('/');
            if (last_slash != std::string::npos) {
                auto id = cgroup.substr(last_slash + 1);
                if (id.length() >= 12) {
                    // Verify it's hex
                    bool hex = std::all_of(id.begin(), id.begin() + 12,
                        [](char c) {
                            return (c >= '0' && c <= '9') ||
                                   (c >= 'a' && c <= 'f') ||
                                   (c >= 'A' && c <= 'F');
                        });
                    if (hex) return id.substr(0, 12);
                }
            }
        }
    }

    // Containerd
    {
        auto pos = cgroup.find("containerd");
        if (pos != std::string::npos) {
            size_t last_slash = cgroup.rfind('/');
            if (last_slash != std::string::npos) {
                auto id = cgroup.substr(last_slash + 1);
                if (id.length() >= 12) return id.substr(0, 12);
            }
        }
    }

    return "";
}

} // namespace fuseviz
