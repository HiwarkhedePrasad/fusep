// ═══════════════════════════════════════════════════════════════════════
//  security_engine.cpp  —  Sliding-Window Heuristic + Ollama Client
// ═══════════════════════════════════════════════════════════════════════

#include "security_engine.h"
#include <nlohmann/json.hpp>
#include <httplib.h>
#include <cstdio>
#include <sstream>
#include <optional>

using json = nlohmann::json;

namespace fuseviz {

SecurityEngine::SecurityEngine(const std::string& ollama_url,
                                const std::string& ollama_model,
                                uint64_t cooldown_ns)
    : ollama_url_(ollama_url), ollama_model_(ollama_model),
      cooldown_ns_(cooldown_ns) {}

void SecurityEngine::start(
    SPSCQueue<EnrichedEvent, 1 << 16>& input_queue,
    AlertCallback alert_callback,
    std::atomic<bool>& running)
{
    alert_callback_ = std::move(alert_callback);
    fprintf(stderr, "[Security] Engine started (Ollama: %s, model: %s)\n",
            ollama_url_.c_str(), ollama_model_.c_str());

    while (running.load(std::memory_order_relaxed)) {
        auto evt_opt = input_queue.pop();
        if (!evt_opt.has_value()) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            continue;
        }

        process_event(evt_opt.value());
    }

    fprintf(stderr, "[Security] Engine stopped\n");
}

void SecurityEngine::process_event(const EnrichedEvent& evt) {
    std::lock_guard<std::mutex> lock(trackers_mutex_);

    auto& tracker = trackers_[evt.raw.pid];
    tracker.process_name = evt.process_name;

    // Push into sliding window
    WindowEntry entry;
    entry.timestamp_ns = evt.raw.timestamp_ns;
    entry.opcode = evt.raw.opcode;
    entry.nodeid = evt.raw.nodeid;
    entry.data_len = evt.raw.data_len;
    tracker.push(entry);

    // Evaluate threat rules
    check_threats(evt.raw.pid, tracker, evt.raw.timestamp_ns, evt);

    // Cleanup idle trackers
    if (trackers_.size() > 4096) {
        uint64_t cutoff = evt.raw.timestamp_ns - 10'000'000'000ULL; // 10s
        for (auto it = trackers_.begin(); it != trackers_.end(); ) {
            if (it->second.window.empty() ||
                it->second.window.back().timestamp_ns < cutoff) {
                it = trackers_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void SecurityEngine::check_threats(uint32_t pid, PIDTracker& tracker,
                                    uint64_t now_ns, const EnrichedEvent& evt) {
    // Check cooldown
    if (now_ns - tracker.last_alert_ns < cooldown_ns_) return;

    // ── Ransomware detection ──
    if (tracker.is_ransomware()) {
        ThreatAlert alert;
        alert.timestamp_ns = now_ns;
        alert.type = ThreatType::Ransomware;
        alert.severity = ThreatSeverity::High;
        alert.pid = pid;
        alert.process_name = tracker.process_name;

        json details;
        details["writes"] = tracker.count_opcode(FUSE_WRITE);
        details["unlinks"] = tracker.count_opcode(FUSE_UNLINK) +
                             tracker.count_opcode(FUSE_RENAME);
        details["rapid_sequence"] = tracker.is_rapid_sequence();
        alert.details_json = details.dump();

        // Dispatch to Ollama for AI analysis
        EnrichedEvent placeholder;
        memset(&placeholder.raw, 0, sizeof(placeholder.raw));
        placeholder.raw.pid = pid;
        placeholder.process_name = tracker.process_name;
        auto analysis = dispatch_ollama(alert, placeholder);
        if (analysis.has_value()) {
            alert.ai_analysis = analysis.value();
            tracker.last_alert_ns = now_ns;
        } else {
            alert.ai_analysis = "AI analysis unavailable";
            // Don't set cooldown — allow retry on next trigger
        }

        if (alert_callback_) {
            alert_callback_(alert);
        }

        fprintf(stderr, "[Security] RANSOMWARE alert for PID %u (%s)\n",
                pid, tracker.process_name.c_str());
    }

    // ── Exfiltration detection ──
    if (tracker.is_exfiltration()) {
        ThreatAlert alert;
        alert.timestamp_ns = now_ns;
        alert.type = ThreatType::Exfiltration;
        alert.severity = ThreatSeverity::Critical;
        alert.pid = pid;
        alert.process_name = tracker.process_name;

        json details;
        details["reads"] = tracker.count_opcode(FUSE_READ);
        uint64_t read_bytes = 0;
        for (auto& e : tracker.window) {
            if (e.opcode == FUSE_READ) read_bytes += e.data_len;
        }
        details["read_bytes"] = read_bytes;
        alert.details_json = details.dump();

        // Dispatch to Ollama for AI analysis
        EnrichedEvent placeholder;
        memset(&placeholder.raw, 0, sizeof(placeholder.raw));
        placeholder.raw.pid = pid;
        placeholder.process_name = tracker.process_name;
        auto analysis = dispatch_ollama(alert, placeholder);
        if (analysis.has_value()) {
            alert.ai_analysis = analysis.value();
            tracker.last_alert_ns = now_ns;
        } else {
            alert.ai_analysis = "AI analysis unavailable";
            // Don't set cooldown — allow retry on next trigger
        }

        if (alert_callback_) {
            alert_callback_(alert);
        }

        fprintf(stderr, "[Security] EXFILTRATION alert for PID %u (%s)\n",
                pid, tracker.process_name.c_str());
    }
}

std::optional<std::string> SecurityEngine::dispatch_ollama(const ThreatAlert& alert,
                                                            const EnrichedEvent& evt) {
    try {
        std::string host = ollama_url_;
        int port = 11434;

        auto proto_end = host.find("://");
        if (proto_end != std::string::npos) {
            host = host.substr(proto_end + 3);
        }

        auto colon = host.find(':');
        if (colon != std::string::npos) {
            port = std::stoi(host.substr(colon + 1));
            host = host.substr(0, colon);
        }

        httplib::Client cli(host, port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(30);

        std::string prompt = "You are a filesystem security analyst. "
            "Analyze this threat alert:\n\n"
            "Type: " + std::string(alert.type == ThreatType::Ransomware ?
                "Ransomware" : "Exfiltration") + "\n"
            "PID: " + std::to_string(alert.pid) + "\n"
            "Process: " + alert.process_name + "\n"
            "Details: " + alert.details_json + "\n\n"
            "Provide risk assessment and recommended action.";

        json req_body = {
            {"model", ollama_model_},
            {"prompt", prompt},
            {"stream", false}
        };

        auto res = cli.Post("/api/generate", req_body.dump(),
                            "application/json");

        if (res && res->status == 200) {
            auto resp = json::parse(res->body, nullptr, false);
            if (!resp.is_null() && resp.contains("response")) {
                return resp["response"].get<std::string>();
            }
        }

        return std::nullopt;
    } catch (const std::exception& e) {
        fprintf(stderr, "[Security/Ollama] Error: %s\n", e.what());
        return std::nullopt;
    }
}

} // namespace fuseviz
