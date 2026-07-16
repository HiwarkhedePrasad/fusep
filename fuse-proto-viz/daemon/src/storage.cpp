// ═══════════════════════════════════════════════════════════════════════
//  storage.cpp  —  SQLite3 WAL Persistence Implementation
// ═══════════════════════════════════════════════════════════════════════

#include "storage.h"
#include <sqlite3.h>
#include <cstdio>
#include <cstring>
#include <chrono>

namespace fuseviz {

Storage::Storage(const std::string& db_path, int batch_size, int flush_interval_ms)
    : db_path_(db_path), batch_size_(batch_size),
      flush_interval_ms_(flush_interval_ms) {}

Storage::~Storage() {
    close();
}

bool Storage::open() {
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Storage] Cannot open database: %s\n",
                sqlite3_errmsg(db_));
        return false;
    }

    // ── Performance PRAGMAs ──
    sqlite3_exec(db_, "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous = NORMAL", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA cache_size = -64000", nullptr, nullptr, nullptr); // 64MB
    sqlite3_exec(db_, "PRAGMA temp_store = MEMORY", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA mmap_size = 134217728", nullptr, nullptr, nullptr); // 128MB
    sqlite3_exec(db_, "PRAGMA page_size = 4096", nullptr, nullptr, nullptr);

    create_schema();

    fprintf(stderr, "[Storage] SQLite WAL database opened: %s\n", db_path_.c_str());
    return true;
}

void Storage::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void Storage::create_schema() {
    const char* schema = R"(
    CREATE TABLE IF NOT EXISTS fuse_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   INTEGER NOT NULL,
        opcode      INTEGER NOT NULL,
        opcode_name TEXT NOT NULL,
        nodeid      INTEGER NOT NULL DEFAULT 0,
        unique_id   INTEGER NOT NULL DEFAULT 0,
        pid         INTEGER NOT NULL,
        uid         INTEGER NOT NULL DEFAULT 0,
        gid         INTEGER NOT NULL DEFAULT 0,
        direction   INTEGER NOT NULL DEFAULT 0,
        error_code  INTEGER NOT NULL DEFAULT 0,
        data_len    INTEGER NOT NULL DEFAULT 0,
        latency_ns  INTEGER NOT NULL DEFAULT 0,
        process_name TEXT NOT NULL DEFAULT '',
        container_id TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON fuse_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_opcode ON fuse_events(opcode);
    CREATE INDEX IF NOT EXISTS idx_events_pid ON fuse_events(pid);

    CREATE TABLE IF NOT EXISTS threat_alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   INTEGER NOT NULL,
        alert_type  TEXT NOT NULL,
        severity    TEXT NOT NULL,
        pid         INTEGER NOT NULL,
        process_name TEXT NOT NULL DEFAULT '',
        details     TEXT NOT NULL,
        ai_analysis TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_ts ON threat_alerts(timestamp);
    )";

    char* err = nullptr;
    int rc = sqlite3_exec(db_, schema, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Storage] Schema error: %s\n", err);
        sqlite3_free(err);
    }
}

void Storage::start(
    SPSCQueue<EnrichedEvent, 1 << 16>& input_queue,
    std::atomic<bool>& running)
{
    fprintf(stderr, "[Storage] Batch writer started (batch=%d)\n", batch_size_);

    std::vector<EnrichedEvent> batch;
    batch.reserve(batch_size_);

    auto last_flush = std::chrono::steady_clock::now();

    while (running.load(std::memory_order_relaxed)) {
        auto evt = input_queue.pop();
        if (evt.has_value()) {
            batch.push_back(std::move(evt.value()));
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_flush).count();

        bool should_flush = (static_cast<int>(batch.size()) >= batch_size_) ||
                           (elapsed >= flush_interval_ms_ && !batch.empty());

        if (should_flush) {
            flush_batch(batch);
            batch.clear();
            batch.reserve(batch_size_);
            last_flush = now;
        }

        if (!evt.has_value()) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }

    // Final flush
    if (!batch.empty()) {
        flush_batch(batch);
    }

    fprintf(stderr, "[Storage] Batch writer stopped\n");
}

void Storage::flush_batch(const std::vector<EnrichedEvent>& batch) {
    if (batch.empty() || !db_) return;

    std::lock_guard<std::mutex> lock(db_mutex_);

    char* err = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err) != SQLITE_OK) {
        fprintf(stderr, "[Storage] Begin transaction error: %s\n", err);
        sqlite3_free(err);
        return;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO fuse_events "
        "(timestamp, opcode, opcode_name, nodeid, unique_id, "
        "pid, uid, gid, direction, error_code, data_len, latency_ns, "
        "process_name, container_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        fprintf(stderr, "[Storage] Prepare error: %s\n", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return;
    }

    bool failed = false;
    for (const auto& evt : batch) {
        sqlite3_bind_int64(stmt, 1,  static_cast<sqlite3_int64>(evt.raw.timestamp_ns));
        sqlite3_bind_int(stmt, 2,    static_cast<int>(evt.raw.opcode));
        sqlite3_bind_text(stmt, 3,   evt.opcode_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4,  static_cast<sqlite3_int64>(evt.raw.nodeid));
        sqlite3_bind_int64(stmt, 5,  static_cast<sqlite3_int64>(evt.raw.unique));
        sqlite3_bind_int(stmt, 6,    static_cast<int>(evt.raw.pid));
        sqlite3_bind_int(stmt, 7,    static_cast<int>(evt.raw.uid));
        sqlite3_bind_int(stmt, 8,    static_cast<int>(evt.raw.gid));
        sqlite3_bind_int(stmt, 9,    static_cast<int>(evt.raw.direction));
        sqlite3_bind_int(stmt, 10,   static_cast<int>(evt.raw.error));
        sqlite3_bind_int(stmt, 11,   static_cast<int>(evt.raw.data_len));
        sqlite3_bind_int64(stmt, 12, static_cast<sqlite3_int64>(evt.raw.latency_ns));
        sqlite3_bind_text(stmt, 13,  evt.process_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 14,  evt.container_id.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "[Storage] Insert error: %s\n", sqlite3_errmsg(db_));
            failed = true;
            break;
        }
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);

    if (failed) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    } else {
        sqlite3_exec(db_, "COMMIT", nullptr, &err, nullptr);
        if (err) {
            fprintf(stderr, "[Storage] Commit error: %s\n", err);
            sqlite3_free(err);
        }
    }
}

void Storage::store_alert(const ThreatAlert& alert) {
    if (!db_) return;
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* type_str = "";
    switch (alert.type) {
        case ThreatType::Ransomware:  type_str = "ransomware_pattern"; break;
        case ThreatType::Exfiltration: type_str = "data_exfiltration"; break;
        case ThreatType::Anomaly:     type_str = "anomaly_detected"; break;
    }

    const char* sev_str = "";
    switch (alert.severity) {
        case ThreatSeverity::Low:      sev_str = "low"; break;
        case ThreatSeverity::Medium:   sev_str = "medium"; break;
        case ThreatSeverity::High:     sev_str = "high"; break;
        case ThreatSeverity::Critical: sev_str = "critical"; break;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO threat_alerts "
        "(timestamp, alert_type, severity, pid, process_name, details, ai_analysis) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Storage] Alert prepare error: %s\n", sqlite3_errmsg(db_));
        return;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(alert.timestamp_ns));
    sqlite3_bind_text(stmt, 2, type_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sev_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, static_cast<int>(alert.pid));
    sqlite3_bind_text(stmt, 5, alert.process_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, alert.details_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, alert.ai_analysis.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[Storage] Alert insert error: %s\n", sqlite3_errmsg(db_));
    }
    sqlite3_finalize(stmt);
}

} // namespace fuseviz
