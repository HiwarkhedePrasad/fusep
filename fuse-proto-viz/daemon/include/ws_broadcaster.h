#pragma once

#include "fuse_types.h"
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <unistd.h>
#include <netinet/in.h>

namespace fuseviz {

class WSBroadcaster {
public:
    WSBroadcaster(const std::string& host, int port, const std::string& ws_secret = "");
    ~WSBroadcaster();

    void start();
    void broadcast_event(const EnrichedEvent& evt);
    void broadcast_alert(const ThreatAlert& alert);
    void broadcast_json(const std::string& json);
    void stop();

    void set_timestamp_offset(int64_t offset_ns) { ts_offset_ns_ = offset_ns; }

private:
    std::string host_;
    int port_;
    std::string ws_secret_;
    int64_t ts_offset_ns_ = 0;
    std::thread thread_;
    std::atomic<bool> running_{false};
    int server_fd_ = -1;

    struct Client {
        int fd;
        uint64_t id;
    };
    std::vector<Client> clients_;
    std::mutex clients_mutex_;

    std::mutex buffer_mutex_;
    std::vector<std::string> recent_events_;
    std::vector<std::string> recent_alerts_;
    static constexpr size_t MAX_RECENT = 500;
    static constexpr size_t MAX_CLIENTS = 128;

    void handle_client(int client_fd);
    ssize_t send_frame(int fd, const std::string& data);
    void broadcast_all(const std::string& data);
    bool do_handshake(int fd, const std::string& request);
};

}
