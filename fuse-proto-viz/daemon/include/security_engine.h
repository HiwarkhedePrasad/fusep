// ═══════════════════════════════════════════════════════════════════════
//  security_engine.h  —  Sliding-Window Heuristic Engine
//
//  In-memory stream processor that tracks operation rates per PID
//  using a std::deque-based sliding window. Detects:
//    - Ransomware: high-freq WRITE + UNLINK/RENAME
//    - Exfiltration: massive read volumes on sensitive nodes
//
//  When thresholds break, dispatches to Ollama for AI analysis.
// ═══════════════════════════════════════════════════════════════════════

#pragma once

#include "fuse_types.h"
#include "spsc_queue.h"
#include <thread>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <string>
#include <functional>

namespace fuseviz {

class SecurityEngine {
public:
    using AlertCallback = std::function<void(const ThreatAlert&)>;

    SecurityEngine(const std::string& ollama_url,
                   const std::string& ollama_model,
                   uint64_t cooldown_ns = 30'000'000'000ULL);

    // Start the security engine worker
    void start(
        SPSCQueue<EnrichedEvent, 1 << 16>& input_queue,
        AlertCallback alert_callback,
        std::atomic<bool>& running
    );

private:
    std::string ollama_url_;
    std::string ollama_model_;
    uint64_t cooldown_ns_;

    std::mutex trackers_mutex_;
    std::unordered_map<uint32_t, PIDTracker> trackers_;
    AlertCallback alert_callback_;

    void process_event(const EnrichedEvent& evt);
    void check_threats(uint32_t pid, PIDTracker& tracker, uint64_t now_ns,
                       const EnrichedEvent& evt);
    std::optional<std::string> dispatch_ollama(const ThreatAlert& alert, const EnrichedEvent& evt);
};

} // namespace fuseviz
