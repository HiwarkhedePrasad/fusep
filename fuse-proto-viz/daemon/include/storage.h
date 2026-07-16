// ═══════════════════════════════════════════════════════════════════════
//  storage.h  —  SQLite3 WAL Persistence Layer
//
//  Opens SQLite in WAL mode with synchronous=NORMAL for crash-safe
//  write throughput. Batches INSERT statements in transactions
//  of 500 events for optimal disk I/O.
// ═══════════════════════════════════════════════════════════════════════

#pragma once

#include "fuse_types.h"
#include "spsc_queue.h"
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>

struct sqlite3;

namespace fuseviz {

class Storage {
public:
    explicit Storage(const std::string& db_path, int batch_size = 500,
                     int flush_interval_ms = 500);
    ~Storage();

    bool open();
    void close();

    // Start the batch writer thread
    void start(
        SPSCQueue<EnrichedEvent, 1 << 16>& input_queue,
        std::atomic<bool>& running
    );

    // Direct insert for alerts (from security engine)
    void store_alert(const ThreatAlert& alert);

    // Query for REST API
    std::vector<EnrichedEvent> query_recent_events(int limit);
    std::vector<ThreatAlert> query_recent_alerts(int limit);

private:
    std::string db_path_;
    int batch_size_;
    int flush_interval_ms_;
    sqlite3* db_ = nullptr;
    std::mutex db_mutex_;

    void create_schema();
    void flush_batch(const std::vector<EnrichedEvent>& batch);
};

} // namespace fuseviz
