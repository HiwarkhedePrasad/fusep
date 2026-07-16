// ═══════════════════════════════════════════════════════════════════════
//  fuse_types.h  —  C++ type definitions for the FuseViz daemon
//
//  Extends the shared fuse_trace.h with C++-specific types for
//  enrichment, security, and WebSocket broadcasting.
// ═══════════════════════════════════════════════════════════════════════

#pragma once

#include <string>
#include <cstdint>
#include <unordered_map>
#include <deque>
#include <chrono>

// Include the shared eBPF ring buffer contract
#include "../../ebpf/fuse_trace.h"

namespace fuseviz {
    // Make the C struct available in fuseviz namespace for template consistency
    using ::fuse_trace_event;

// ── Opcode name lookup ──
struct OpcodeNames {
    static const char* get(uint32_t opcode) {
        switch (opcode) {
            case FUSE_LOOKUP:         return "FUSE_LOOKUP";
            case FUSE_FORGET:         return "FUSE_FORGET";
            case FUSE_GETATTR:        return "FUSE_GETATTR";
            case FUSE_SETATTR:        return "FUSE_SETATTR";
            case FUSE_READLINK:       return "FUSE_READLINK";
            case FUSE_SYMLINK:        return "FUSE_SYMLINK";
            case FUSE_MKNOD:          return "FUSE_MKNOD";
            case FUSE_MKDIR:          return "FUSE_MKDIR";
            case FUSE_UNLINK:         return "FUSE_UNLINK";
            case FUSE_RMDIR:          return "FUSE_RMDIR";
            case FUSE_RENAME:         return "FUSE_RENAME";
            case FUSE_LINK:           return "FUSE_LINK";
            case FUSE_OPEN:           return "FUSE_OPEN";
            case FUSE_READ:           return "FUSE_READ";
            case FUSE_WRITE:          return "FUSE_WRITE";
            case FUSE_STATFS:         return "FUSE_STATFS";
            case FUSE_RELEASE:        return "FUSE_RELEASE";
            case FUSE_FSYNC:          return "FUSE_FSYNC";
            case FUSE_SETXATTR:       return "FUSE_SETXATTR";
            case FUSE_GETXATTR:       return "FUSE_GETXATTR";
            case FUSE_LISTXATTR:      return "FUSE_LISTXATTR";
            case FUSE_REMOVEXATTR:    return "FUSE_REMOVEXATTR";
            case FUSE_FLUSH:          return "FUSE_FLUSH";
            case FUSE_INIT:           return "FUSE_INIT";
            case FUSE_OPENDIR:        return "FUSE_OPENDIR";
            case FUSE_READDIR:        return "FUSE_READDIR";
            case FUSE_RELEASEDIR:     return "FUSE_RELEASEDIR";
            case FUSE_FSYNCDIR:       return "FUSE_FSYNCDIR";
            case FUSE_ACCESS:         return "FUSE_ACCESS";
            case FUSE_CREATE:         return "FUSE_CREATE";
            case FUSE_INTERRUPT:      return "FUSE_INTERRUPT";
            case FUSE_BMAP:           return "FUSE_BMAP";
            case FUSE_DESTROY:        return "FUSE_DESTROY";
            case FUSE_IOCTL:          return "FUSE_IOCTL";
            case FUSE_POLL:           return "FUSE_POLL";
            case FUSE_BATCH_FORGET:   return "FUSE_BATCH_FORGET";
            case FUSE_READDIRPLUS:    return "FUSE_READDIRPLUS";
            case FUSE_RENAME2:        return "FUSE_RENAME2";
            case FUSE_LSEEK:          return "FUSE_LSEEK";
            case FUSE_COPY_FILE_RANGE: return "FUSE_COPY_FILE_RANGE";
            default:                  return "UNKNOWN";
        }
    }
};

// ── Enriched event (after metadata resolution) ──
struct EnrichedEvent {
    struct fuse_trace_event raw;
    std::string opcode_name;
    std::string process_name;
    std::string container_id;
    std::string pod_name;
    std::string namespace_;
};

// ── Threat alert (from security engine) ──
enum class ThreatSeverity { Low, Medium, High, Critical };
enum class ThreatType { Ransomware, Exfiltration, Anomaly };

struct ThreatAlert {
    uint64_t timestamp_ns;
    ThreatType type;
    ThreatSeverity severity;
    uint32_t pid;
    std::string process_name;
    std::string details_json;
    std::string ai_analysis;
};

// ── Security: sliding window entry ──
struct WindowEntry {
    uint64_t timestamp_ns;
    uint32_t opcode;
    uint64_t nodeid;
    uint32_t data_len;
};

// ── Security: per-PID tracker ──
struct PIDTracker {
    std::deque<WindowEntry> window;
    std::string process_name;
    uint64_t last_alert_ns = 0;
    static constexpr size_t MAX_WINDOW = 200;
    static constexpr uint64_t SLIDING_WINDOW_NS = 5'000'000'000ULL; // 5 seconds
    static constexpr uint64_t THREAT_WINDOW_NS = 3'000'000'000ULL; // 3 seconds (for rapid-sequence check)

    void push(const WindowEntry& entry) {
        window.push_back(entry);
        // Evict entries older than the sliding window
        uint64_t cutoff = entry.timestamp_ns - SLIDING_WINDOW_NS;
        while (!window.empty() && window.front().timestamp_ns < cutoff) {
            window.pop_front();
        }
        // Cap window size
        while (window.size() > MAX_WINDOW) {
            window.pop_front();
        }
    }

    // Count operations of a specific opcode within the sliding window
    size_t count_opcode(uint32_t opcode) const {
        size_t count = 0;
        for (auto& e : window) {
            if (e.opcode == opcode) count++;
        }
        return count;
    }

    // Check if window is within the threat threshold
    bool is_rapid_sequence() const {
        if (window.size() < 100) return false;
        return (window.back().timestamp_ns - window.front().timestamp_ns)
            < THREAT_WINDOW_NS;
    }

    // Ransomware: high WRITE + UNLINK/RENAME
    bool is_ransomware() const {
        size_t writes  = count_opcode(FUSE_WRITE);
        size_t unlinks = count_opcode(FUSE_UNLINK) + count_opcode(FUSE_RENAME)
                       + count_opcode(FUSE_RMDIR) + count_opcode(FUSE_RENAME2);
        return writes > 50 && unlinks > 20;
    }

    // Exfiltration: massive reads
    bool is_exfiltration() const {
        size_t reads = count_opcode(FUSE_READ);
        uint64_t read_bytes = 0;
        for (auto& e : window) {
            if (e.opcode == FUSE_READ) read_bytes += e.data_len;
        }
        return reads > 200 && read_bytes > 10 * 1024 * 1024;
    }
};

// ── Configuration ──
struct Config {
    std::string bpf_object_path = "/opt/fuseviz/ebpf/fuse_trace.bpf.o";
    std::string db_path = "/var/lib/fuseviz/events.db";
    std::string listen_host = "0.0.0.0";
    int listen_port = 8080;
    std::string ollama_url = "http://localhost:11434";
    std::string ollama_model = "llama3";
    std::string ws_secret;
    int batch_size = 500;
    int flush_interval_ms = 500;
    uint64_t alert_cooldown_ns = 30'000'000'000ULL; // 30 seconds
};

} // namespace fuseviz
