#pragma once

#include <string>
#include <functional>
#include <memory>
#include <atomic>

#ifdef HAVE_LIBBPF
struct bpf_object;
struct bpf_link;
struct ring_buffer;
#endif

#include "fuse_trace.h"

namespace fuseviz {

class BPFLoader {
public:
    using EventCallback = std::function<void(const struct fuse_trace_event&)>;

    BPFLoader(const std::string& bpf_object_path);
    ~BPFLoader();

    bool load_and_attach();
    void poll(EventCallback callback, std::atomic<bool>& running);
    void close();

private:
    std::string bpf_object_path_;
#ifdef HAVE_LIBBPF
    struct bpf_object* obj_ = nullptr;
    struct ring_buffer* rb_ = nullptr;
    void* rb_ctx_ = nullptr;
    struct bpf_link* read_link_ = nullptr;
    struct bpf_link* write_link_ = nullptr;
    bool loaded_ = false;
    static int handle_event(void* ctx, void* data, size_t size);
#endif
};

}
