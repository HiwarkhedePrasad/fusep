#include "ws_broadcaster.h"
#include "fuse_trace.h"

#include <nlohmann/json.hpp>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <string>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <algorithm>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

using json = nlohmann::json;

namespace fuseviz {

WSBroadcaster::WSBroadcaster(const std::string& host, int port, const std::string& ws_secret)
    : host_(host), port_(port), ws_secret_(ws_secret) {}

WSBroadcaster::~WSBroadcaster() { stop(); }

// Base64 encoding
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const unsigned char* data, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        unsigned char b0 = data[i];
        unsigned char b1 = i + 1 < len ? data[i + 1] : 0;
        unsigned char b2 = i + 2 < len ? data[i + 2] : 0;
        out += b64_table[b0 >> 2];
        out += b64_table[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += (i + 1 < len) ? b64_table[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=';
        out += (i + 2 < len) ? b64_table[b2 & 0x3F] : '=';
    }
    return out;
}

// Extract query parameter value from a URI query string
static std::string get_query_param(const std::string& uri, const std::string& param) {
    auto qpos = uri.find('?');
    if (qpos == std::string::npos) return "";
    std::string qs = uri.substr(qpos + 1);
    std::string target = param + "=";
    auto ppos = qs.find(target);
    if (ppos == std::string::npos) return "";
    auto start = ppos + target.size();
    auto end = qs.find('&', start);
    return qs.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

// Extract header value by name from HTTP request
static std::string get_header_value(const std::string& request, const std::string& header) {
    std::string target = header + ": ";
    auto pos = request.find(target);
    if (pos == std::string::npos) {
        // Try lowercase
        std::string lower = header;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        target = lower + ": ";
        pos = request.find(target);
        if (pos == std::string::npos) return "";
    }
    pos += target.size();
    auto end = request.find("\r\n", pos);
    return request.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

bool WSBroadcaster::do_handshake(int fd, const std::string& request) {
    // Authenticate before sending any response
    if (!ws_secret_.empty()) {
        std::string protocol = get_header_value(request, "Sec-WebSocket-Protocol");
        std::string api_key = get_header_value(request, "x-api-key");

        bool authed = (protocol == ws_secret_) || (api_key == ws_secret_);
        if (!authed) {
            std::string resp =
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            write(fd, resp.data(), resp.size());
            return false;
        }
    }

    // WebSocket upgrade handshake
    auto key_val = get_header_value(request, "Sec-WebSocket-Key");
    if (key_val.empty()) return false;

    std::string magic = key_val + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char sha[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(magic.data()), magic.size(), sha);
    std::string accept = base64_encode(sha, SHA_DIGEST_LENGTH);

    std::string protocol = get_header_value(request, "Sec-WebSocket-Protocol");
    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n";
    if (!protocol.empty())
        response += "Sec-WebSocket-Protocol: " + protocol + "\r\n";
    response += "\r\n";

    write(fd, response.data(), response.size());
    return true;
}

ssize_t WSBroadcaster::send_frame(int fd, const std::string& data) {
    unsigned char header[10];
    size_t header_len;
    size_t len = data.size();

    header[0] = 0x81; // FIN + text opcode
    if (len < 126) {
        header[1] = len;
        header_len = 2;
    } else if (len < 65536) {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        header_len = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++)
            header[2 + i] = (len >> (56 - i * 8)) & 0xFF;
        header_len = 10;
    }

    // Write header + payload together using writev for atomicity
    struct iovec iov[2];
    iov[0].iov_base = header;
    iov[0].iov_len = header_len;
    iov[1].iov_base = const_cast<char*>(data.data());
    iov[1].iov_len = len;
    return writev(fd, iov, 2);
}

void WSBroadcaster::broadcast_all(const std::string& data) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    for (auto it = clients_.begin(); it != clients_.end(); ) {
        ssize_t w = send_frame(it->fd, data);
        if (w <= 0) {
            // Write failed — client is dead, remove it
            fprintf(stderr, "[WS] Write failed for fd=%d, removing dead client\n", it->fd);
            close(it->fd);
            it = clients_.erase(it);
        } else {
            ++it;
        }
    }
}

// ── Read the full HTTP request, looping until we see the end-of-headers
//    marker (\r\n\r\n) or hit the timeout. A single read() can return only
//    the first TCP segment of the request, which may not contain all headers.
static std::string read_full_request(int fd, int timeout_ms = 3000) {
    // Set a receive timeout so we don't block forever on a half-open connection
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::string request;
    char buf[4096];

    for (int attempt = 0; attempt < 20; ++attempt) { // max 20 reads
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';
        request.append(buf, n);

        // Check for end of HTTP headers
        if (request.find("\r\n\r\n") != std::string::npos)
            break;
    }

    // Restore to blocking for the WebSocket read loop
    struct timeval tv_zero = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_zero, sizeof(tv_zero));

    return request;
}

void WSBroadcaster::handle_client(int client_fd) {
    // ── Enable TCP_NODELAY to prevent Nagle buffering the 101 handshake ──
    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    // ── Read the full HTTP upgrade request (may span multiple TCP segments) ──
    std::string request = read_full_request(client_fd);
    if (request.empty()) {
        close(client_fd);
        return;
    }

    fprintf(stderr, "[WS] Request: %.80s...\n", request.c_str());

    // ── Route the request ──
    if (request.find("Sec-WebSocket-Key: ") != std::string::npos) {
        // WebSocket upgrade
        if (!do_handshake(client_fd, request)) {
            fprintf(stderr, "[WS] Handshake failed or unauthorized\n");
            close(client_fd);
            return;
        }
    } else if (request.find("GET /api/health") == 0) {
        json j = {{"status", "ok"}, {"version", "2.0.0-cpp"}};
        std::string body = j.dump();
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        write(client_fd, resp.data(), resp.size());
        close(client_fd);
        return;
    } else if (request.find("GET /api/stats") == 0) {
        json j = {{"backend", "c++20"}, {"engine", "simple_ws"}, {"persistence", "SQLite WAL"}};
        std::string body = j.dump();
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        write(client_fd, resp.data(), resp.size());
        close(client_fd);
        return;
    } else {
        fprintf(stderr, "[WS] Unknown request, sending 404\n");
        std::string resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        write(client_fd, resp.data(), resp.size());
        close(client_fd);
        return;
    }

    uint64_t id = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());

    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.push_back({client_fd, id});
    }
    fprintf(stderr, "[WS] Client connected (fd=%d, id=%lu)\n", client_fd, (unsigned long)id);

    // Send recent events for catchup (lock clients_mutex_ to prevent
    // concurrent write from broadcast_all thread corrupting frames)
    {
        std::lock_guard<std::mutex> lock(buffer_mutex_);
        std::lock_guard<std::mutex> lock_clients(clients_mutex_);
        for (const auto& evt_json : recent_events_)
            send_frame(client_fd, evt_json);
    }

    // ── Read loop: handle pings/pongs, detect disconnection ──
    // Set a generous receive timeout to detect dead connections
    {
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    char buf[4096];
    while (running_.load()) {
        ssize_t n = read(client_fd, buf, sizeof(buf));
        if (n <= 0) {
            // Timeout (EAGAIN/EWOULDBLOCK) or connection closed
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // 30-second timeout with no data — send a ping to check liveness
                unsigned char ping[2] = {0x89, 0x00}; // FIN + PING opcode
                ssize_t w = write(client_fd, ping, 2);
                if (w <= 0) {
                    fprintf(stderr, "[WS] Ping failed for fd=%d, closing\n", client_fd);
                    break;
                }
                // Give the client another chance to respond (or send data)
                continue;
            }
            break; // Real error or clean close
        }

        // Handle close frame and pings
        bool should_close = false;
        for (ssize_t i = 0; i < n; ) {
            if (i + 1 >= n) break; // need at least 2 bytes for header

            unsigned char opcode = buf[i] & 0x0F;
            bool fin = buf[i] & 0x80;
            size_t payload_len = buf[i+1] & 0x7F;
            bool masked = buf[i+1] & 0x80;
            size_t header_size = 2 + (masked ? 4 : 0);
            if (payload_len == 126) {
                if (i + 4 > n) break;
                payload_len = ((unsigned char)buf[i+2] << 8) | (unsigned char)buf[i+3];
                header_size = 4 + (masked ? 4 : 0);
            } else if (payload_len == 127) {
                if (i + 10 > n) break;
                payload_len = 0;
                for (int j = 0; j < 8; j++)
                    payload_len = (payload_len << 8) | (unsigned char)buf[i+2+j];
                header_size = 10 + (masked ? 4 : 0);
            }

            // Ensure we have the full frame before processing
            if (i + header_size + (int)payload_len > n) break;

            if (opcode == 0x8) { // Close frame — respond with close and disconnect
                // Send close frame back (opcode 0x88)
                unsigned char close_frame[2] = {0x88, 0x00};
                write(client_fd, close_frame, 2);
                should_close = true;
                break;
            } else if (opcode == 0x9) { // Ping — respond with pong
                unsigned char pong[2] = {0x8A, 0x00};
                write(client_fd, pong, 2);
            }
            // Pong (0xA) and text (0x1) frames — just skip them

            i += header_size + payload_len;
        }

        if (should_close) break;
    }

    // ── Cleanup ──
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
            [client_fd](const Client& c) { return c.fd == client_fd; }),
            clients_.end());
    }
    close(client_fd);
    fprintf(stderr, "[WS] Client disconnected (fd=%d)\n", client_fd);
}

void WSBroadcaster::start() {
    running_ = true;

    thread_ = std::thread([this]() {
        // Use IPv6 dual-stack (accepts both IPv4 and IPv6 connections)
        server_fd_ = socket(AF_INET6, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            // Fall back to IPv4 if IPv6 is unavailable
            server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
            if (server_fd_ < 0) {
                fprintf(stderr, "[WS] Failed to create socket\n");
                return;
            }
        }

        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        // Enable TCP_NODELAY on the server socket so new connections inherit it
        setsockopt(server_fd_, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        int v6only = 0;
        setsockopt(server_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port_);
        addr6.sin6_addr = in6addr_any;

        if (bind(server_fd_, (struct sockaddr*)&addr6, sizeof(addr6)) < 0) {
            // Fall back to IPv4
            close(server_fd_);
            server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
            if (server_fd_ < 0) {
                fprintf(stderr, "[WS] Failed to create socket\n");
                return;
            }
            setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in addr4;
            memset(&addr4, 0, sizeof(addr4));
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(port_);
            if (host_ == "0.0.0.0" || host_.empty()) {
                addr4.sin_addr.s_addr = INADDR_ANY;
            } else {
                struct addrinfo hints, *res;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                if (getaddrinfo(host_.c_str(), nullptr, &hints, &res) == 0 && res) {
                    addr4.sin_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
                    freeaddrinfo(res);
                } else {
                    addr4.sin_addr.s_addr = inet_addr(host_.c_str());
                }
            }
            if (bind(server_fd_, (struct sockaddr*)&addr4, sizeof(addr4)) < 0) {
                fprintf(stderr, "[WS] Failed to bind to %s:%d\n", host_.c_str(), port_);
                close(server_fd_);
                server_fd_ = -1;
                return;
            }
        }

        listen(server_fd_, SOMAXCONN);
        fprintf(stderr, "[WS] Listening on %s:%d\n", host_.c_str(), port_);

        fd_set readfds;
        while (running_.load()) {
            FD_ZERO(&readfds);
            FD_SET(server_fd_, &readfds);
            struct timeval tv = {1, 0};

            int ret = select(server_fd_ + 1, &readfds, nullptr, nullptr, &tv);
            if (ret > 0 && FD_ISSET(server_fd_, &readfds)) {
                // Limit concurrent clients
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    if (clients_.size() >= MAX_CLIENTS) {
                        struct sockaddr_in dummy;
                        socklen_t dummy_len = sizeof(dummy);
                        int rejected = accept(server_fd_, (struct sockaddr*)&dummy, &dummy_len);
                        if (rejected >= 0) close(rejected);
                        continue;
                    }
                }
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(server_fd_,
                    (struct sockaddr*)&client_addr, &client_len);
                if (client_fd >= 0) {
                    std::thread([this, client_fd]() {
                        handle_client(client_fd);
                    }).detach();
                }
            }
        }

        if (server_fd_ >= 0) {
            close(server_fd_);
            server_fd_ = -1;
        }
        fprintf(stderr, "[WS] Server stopped\n");
    });
}

static const char* direction_to_string(uint8_t dir) {
    switch (dir) {
        case FUSE_DIR_READ_ENTER:  return "enter";
        case FUSE_DIR_READ_EXIT:   return "exit";
        case FUSE_DIR_WRITE_ENTER: return "exit";  // write = response going back to kernel
        case FUSE_DIR_WRITE_EXIT:  return "enter";
        default: return "enter";
    }
}

void WSBroadcaster::broadcast_event(const EnrichedEvent& evt) {
    uint64_t ts = evt.raw.timestamp_ns + ts_offset_ns_;
    json j = {
        {"type", "event"},
        {"data", {
            {"ts", ts},
            {"op", evt.raw.opcode},
            {"op_name", evt.opcode_name},
            {"node", evt.raw.nodeid},
            {"unique", evt.raw.unique},
            {"pid", evt.raw.pid},
            {"uid", evt.raw.uid},
            {"gid", evt.raw.gid},
            {"dir", direction_to_string(evt.raw.direction)},
            {"error", evt.raw.error},
            {"data_len", evt.raw.data_len},
            {"latency_ns", evt.raw.latency_ns},
            {"process_name", evt.process_name},
            {"container_id", evt.container_id},
            {"pod_name", evt.pod_name},
            {"namespace", evt.namespace_}
        }}
    };

    /* Include write payload for FUSE_WRITE events */
    if (evt.raw.opcode == FUSE_WRITE && evt.raw.write_data_len > 0) {
        uint8_t len = evt.raw.write_data_len;
        j["data"]["write_data_b64"] = base64_encode(evt.raw.write_data, len);

        /* Also include as text (non-printable chars replaced with '.') */
        std::string text;
        text.reserve(len);
        for (uint8_t i = 0; i < len; i++) {
            uint8_t c = evt.raw.write_data[i];
            text += (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        j["data"]["write_data_text"] = text;
        j["data"]["write_data_len"] = (int)len;
    }

    broadcast_json(j.dump());

    std::lock_guard<std::mutex> lock(buffer_mutex_);
    recent_events_.push_back(j.dump());
    if (recent_events_.size() > MAX_RECENT)
        recent_events_.erase(recent_events_.begin(),
            recent_events_.end() - MAX_RECENT);
}

void WSBroadcaster::broadcast_alert(const ThreatAlert& alert) {
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

    json j = {
        {"type", "alert"},
        {"data", {
            {"ts", alert.timestamp_ns},
            {"type", type_str},
            {"severity", sev_str},
            {"pid", alert.pid},
            {"process_name", alert.process_name},
            {"details", json::parse(alert.details_json, nullptr, false)},
            {"ai_analysis", alert.ai_analysis}
        }}
    };

    broadcast_json(j.dump());
}

void WSBroadcaster::broadcast_json(const std::string& json_str) {
    broadcast_all(json_str);
}

void WSBroadcaster::stop() {
    running_ = false;
    if (thread_.joinable())
        thread_.join();
    if (server_fd_ >= 0) {
        close(server_fd_);
        server_fd_ = -1;
    }
}

}
