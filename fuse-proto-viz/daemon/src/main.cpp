// ═══════════════════════════════════════════════════════════════════════
//  main.cpp  —  FuseViz C++20 Systems Daemon
//
//  The core orchestrator. Launches all pipeline stages:
//    1. BPF ring buffer poller → SPSC queue
//    2. Metadata enricher → SPSC queue
//    3. SQLite WAL batch writer
//    4. Security heuristic engine
//    5. WebSocket broadcaster
//
//  Architecture: Lock-free pipeline with typed SPSC queues.
//  Each stage runs in its own thread.
// ═══════════════════════════════════════════════════════════════════════

#include "fuse_types.h"
#include "spsc_queue.h"
#include "bpf_loader.h"
#include "enricher.h"
#include "storage.h"
#include "ws_broadcaster.h"
#include "security_engine.h"

#include <cstdio>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <cstring>
#include <memory>
#include <random>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static std::atomic<bool> g_running{true};

static void signal_handler(int sig) {
    fprintf(stderr, "\n[FuseViz] Caught signal %d. Shutting down...\n", sig);
    g_running.store(false);
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "════════════════════════════════════════════════════════\n");
    fprintf(stderr, "  FuseViz Systems Daemon v2.0.0-cpp\n");
    fprintf(stderr, "  C++20 | libbpf | simple_ws | SQLite WAL\n");
    fprintf(stderr, "════════════════════════════════════════════════════════\n\n");

    // ── Store start time and compute epoch offset for timestamps ──
    auto start_time = std::chrono::steady_clock::now();
    auto wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto steady_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    int64_t epoch_offset_ns = wall_ns - steady_ns;

    // ── Signal handling ──
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    // ── Configuration ──
    fuseviz::Config config;
    const char* env;

    if ((env = std::getenv("FUSEVIZ_BPF_OBJ")))
        config.bpf_object_path = env;
    if ((env = std::getenv("FUSEVIZ_DB_PATH")))
        config.db_path = env;
    if ((env = std::getenv("FUSEVIZ_LISTEN_PORT")))
        config.listen_port = std::stoi(env);
    if ((env = std::getenv("FUSEVIZ_OLLAMA_URL")))
        config.ollama_url = env;
    if ((env = std::getenv("FUSEVIZ_OLLAMA_MODEL")))
        config.ollama_model = env;
    if ((env = std::getenv("FUSEVIZ_WS_SECRET")))
        config.ws_secret = env;

    // ── Pipeline queues (heap-allocated to avoid stack overflow) ──
    // Queue 1: Raw events from eBPF → Enricher
    auto raw_queue = std::make_unique<fuseviz::SPSCQueue<struct fuse_trace_event, 1 << 16>>();
    // Queue 2: Enriched events → Distribution → Security + Storage
    auto enriched_queue = std::make_unique<fuseviz::SPSCQueue<fuseviz::EnrichedEvent, 1 << 16>>();
    // Queue 3: Distribution → Security engine
    auto security_queue = std::make_unique<fuseviz::SPSCQueue<fuseviz::EnrichedEvent, 1 << 16>>();
    // Queue 4: Distribution → Storage writer
    auto storage_queue = std::make_unique<fuseviz::SPSCQueue<fuseviz::EnrichedEvent, 1 << 16>>();

    // ── Stage 1: BPF Loader + Ring Buffer Poller ──
    fuseviz::BPFLoader bpf_loader(config.bpf_object_path);

    bool bpf_ok = false;
    if (bpf_loader.load_and_attach()) {
        bpf_ok = true;
        fprintf(stderr, "[OK] eBPF engine loaded\n");
    } else {
        fprintf(stderr, "[WARN] eBPF load failed — falling back to simulation mode\n");
    }

    // ── Stage 2: Metadata Enricher ──
    fuseviz::Enricher enricher;

    // ── Stage 3: SQLite WAL Persistence ──
    fuseviz::Storage storage(config.db_path, config.batch_size,
                              config.flush_interval_ms);
    if (!storage.open()) {
        fprintf(stderr, "[FATAL] Cannot open SQLite database\n");
        return 1;
    }
    fprintf(stderr, "[OK] SQLite WAL persistence opened\n");

    // ── Stage 4: WebSocket Broadcaster ──
    fuseviz::WSBroadcaster ws_broadcaster(config.listen_host,
                                           config.listen_port,
                                           config.ws_secret);
    ws_broadcaster.set_timestamp_offset(epoch_offset_ns);
    ws_broadcaster.start();
    fprintf(stderr, "[OK] WebSocket broadcaster started on %s:%d\n",
            config.listen_host.c_str(), config.listen_port);

    // ── Stage 5: Security Engine ──
    fuseviz::SecurityEngine sec_engine(config.ollama_url,
                                        config.ollama_model,
                                        config.alert_cooldown_ns);

    // Security alert callback: broadcast + persist
    auto alert_callback = [&](const fuseviz::ThreatAlert& alert) {
        ws_broadcaster.broadcast_alert(alert);
        storage.store_alert(alert);
    };

    // ── Drop counters for pipeline observability ──
    std::atomic<uint64_t> raw_dropped{0};
    std::atomic<uint64_t> enriched_dropped{0};

    // ── Launch worker threads ──

    // Thread: BPF ring buffer poller
    std::thread bpf_thread;
    if (bpf_ok) {
        bpf_thread = std::thread([&]() {
            bpf_loader.poll([&](const struct fuse_trace_event& evt) {
                if (!raw_queue->push(evt)) {
                    raw_dropped.fetch_add(1, std::memory_order_relaxed);
                }
            }, g_running);
        });
    } else {
        // Simulation mode: generate synthetic FUSE events
        bpf_thread = std::thread([&]() {
            fprintf(stderr, "[SIM] Generating synthetic FUSE events...\n");
            uint64_t counter = 0;
            uint32_t opcodes[] = {15, 16, 3, 1, 14, 28, 18, 25, 10, 12};
            thread_local std::mt19937 rng{std::random_device{}()};
            std::uniform_int_distribution<uint32_t> data_dist(0, 65535);
            std::uniform_int_distribution<uint32_t> lat_dist(50000, 5050000);
            while (g_running.load()) {
                struct fuse_trace_event evt;
                memset(&evt, 0, sizeof(evt));
                evt.timestamp_ns = static_cast<uint64_t>(
                    std::chrono::steady_clock::now().time_since_epoch().count());
                evt.opcode = opcodes[counter % 10];
                evt.unique = ++counter;
                evt.nodeid = (counter % 100) + 1;
                evt.pid = 1000 + (counter % 5) * 1000;
                evt.uid = 1000;
                evt.gid = 1000;
                evt.direction = (counter % 2 == 0) ? 1 : 2;
                evt.data_len = (evt.opcode == 16) ?
                    (data_dist(rng) % 65536) : (data_dist(rng) % 4096);
                evt.latency_ns = lat_dist(rng);
                evt.error = 0;

                if (!raw_queue->push(evt)) {
                    raw_dropped.fetch_add(1, std::memory_order_relaxed);
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }

    // Thread: Enricher
    std::thread enricher_thread([&]() {
        enricher.start(*raw_queue, *enriched_queue, g_running);
    });

    // Thread: Enriched → Distribution → Security + Storage + WebSocket
    std::thread distribution_thread([&]() {
        fprintf(stderr, "[OK] Distribution pipeline started\n");
        uint64_t event_count = 0;
        uint64_t batch_count = 0;
        auto last_stats = std::chrono::steady_clock::now();

        while (g_running.load()) {
            auto evt = enriched_queue->pop();
            if (!evt.has_value()) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));

                // Periodically broadcast stats even when idle
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats).count();
                if (elapsed >= 1) {
                    last_stats = now;
                    uint64_t dropped = raw_dropped.load(std::memory_order_relaxed) +
                                       enriched_dropped.load(std::memory_order_relaxed) +
                                       enricher.dropped_count();
                    json j = {
                        {"type", "stats"},
                        {"data", {
                            {"totalEvents", event_count},
                            {"eventsPerSec", batch_count / (elapsed > 0 ? elapsed : 1)},
                            {"dropped", dropped},
                            {"uptimeSec", static_cast<uint64_t>(
                                std::chrono::duration_cast<std::chrono::seconds>(
                                    now - start_time).count())},
                            {"latency", {{"p50", 0}, {"p90", 0}, {"p99", 0}}},
                            {"opcodeDistribution", json::object()},
                            {"throughputHistory", json::array()},
                            {"activeClients", 0}
                        }}
                    };
                    ws_broadcaster.broadcast_json(j.dump());
                    batch_count = 0;
                }
                continue;
            }

            event_count++;
            batch_count++;

            // Broadcast to WebSocket
            ws_broadcaster.broadcast_event(evt.value());

            // Push to security engine
            if (!security_queue->push(evt.value())) {
                enriched_dropped.fetch_add(1, std::memory_order_relaxed);
            }

            // Push to storage via dedicated queue
            if (!storage_queue->push(evt.value())) {
                enriched_dropped.fetch_add(1, std::memory_order_relaxed);
            }

            // Broadcast stats every ~100 events
            if (batch_count >= 100) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats).count();
                if (elapsed >= 1) {
                    uint64_t dropped = raw_dropped.load(std::memory_order_relaxed) +
                                       enriched_dropped.load(std::memory_order_relaxed) +
                                       enricher.dropped_count();
                    uint64_t rate = batch_count / (elapsed > 0 ? elapsed : 1);
                    last_stats = now;
                    json j = {
                        {"type", "stats"},
                        {"data", {
                            {"totalEvents", event_count},
                            {"eventsPerSec", rate},
                            {"dropped", dropped},
                            {"uptimeSec", static_cast<uint64_t>(
                                std::chrono::duration_cast<std::chrono::seconds>(
                                    now - start_time).count())},
                            {"latency", {{"p50", 0}, {"p90", 0}, {"p99", 0}}},
                            {"opcodeDistribution", json::object()},
                            {"throughputHistory", json::array()},
                            {"activeClients", 0}
                        }}
                    };
                    ws_broadcaster.broadcast_json(j.dump());
                    batch_count = 0;
                }
            }
        }
    });

    // Thread: SQLite batch writer
    std::thread storage_thread([&]() {
        storage.start(*storage_queue, g_running);
    });

    // Thread: Security engine
    std::thread security_thread([&]() {
        sec_engine.start(*security_queue, alert_callback, g_running);
    });

    fprintf(stderr, "\n[FuseViz] All pipelines active. Press Ctrl+C to exit.\n\n");

    // ── Wait for shutdown ──
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // ── Graceful shutdown ──
    fprintf(stderr, "\n[FuseViz] Shutting down...\n");

    if (bpf_thread.joinable()) bpf_thread.join();
    if (enricher_thread.joinable()) enricher_thread.join();
    if (distribution_thread.joinable()) distribution_thread.join();
    if (storage_thread.joinable()) storage_thread.join();
    if (security_thread.joinable()) security_thread.join();

    ws_broadcaster.stop();
    storage.close();
    bpf_loader.close();

    fprintf(stderr, "[FuseViz] Shutdown complete.\n");
    return 0;
}
