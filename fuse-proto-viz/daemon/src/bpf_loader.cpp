#include "bpf_loader.h"
#include "fuse_trace.h"
#include <cstdio>

#ifdef HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <cstring>
#include <unistd.h>
#endif

namespace fuseviz {

#ifdef HAVE_LIBBPF

struct RBContext {
    BPFLoader::EventCallback callback;
};

BPFLoader::BPFLoader(const std::string& bpf_object_path)
    : bpf_object_path_(bpf_object_path) {}

BPFLoader::~BPFLoader() { close(); }

bool BPFLoader::load_and_attach() {
    obj_ = bpf_object__open(bpf_object_path_.c_str());
    if (!obj_) {
        fprintf(stderr, "[BPF] Failed to open BPF object: %s\n",
                bpf_object_path_.c_str());
        return false;
    }

    if (bpf_object__load(obj_) != 0) {
        fprintf(stderr, "[BPF] Failed to load BPF object into kernel\n");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    struct bpf_program* prog;
    prog = bpf_object__find_program_by_name(obj_, "fuse_dev_read_exit");
    if (prog) {
        read_link_ = bpf_program__attach(prog);
        if (!read_link_)
            fprintf(stderr, "[BPF] Failed to attach fexit/fuse_dev_read\n");
        else
            fprintf(stderr, "[BPF] Attached fexit/fuse_dev_read\n");
    } else {
        fprintf(stderr, "[BPF] Program fuse_dev_read_exit not found\n");
    }

    prog = bpf_object__find_program_by_name(obj_, "fuse_dev_write_exit");
    if (prog) {
        write_link_ = bpf_program__attach(prog);
        if (!write_link_)
            fprintf(stderr, "[BPF] Failed to attach fexit/fuse_dev_write\n");
        else
            fprintf(stderr, "[BPF] Attached fexit/fuse_dev_write\n");
    } else {
        fprintf(stderr, "[BPF] Program fuse_dev_write_exit not found\n");
    }

    struct bpf_map* rb_map = bpf_object__find_map_by_name(obj_, "fuse_events_rb");
    if (!rb_map) {
        fprintf(stderr, "[BPF] Ring buffer map not found\n");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    int rb_fd = bpf_map__fd(rb_map);
    rb_ctx_ = new RBContext();
    rb_ = ring_buffer__new(rb_fd, handle_event, rb_ctx_, nullptr);
    if (!rb_) {
        fprintf(stderr, "[BPF] Failed to create ring buffer consumer\n");
        delete static_cast<RBContext*>(rb_ctx_);
        rb_ctx_ = nullptr;
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    loaded_ = true;
    fprintf(stderr, "[BPF] eBPF engine loaded and ready\n");
    return true;
}

int BPFLoader::handle_event(void* ctx, void* data, size_t size) {
    RBContext* rbctx = static_cast<RBContext*>(ctx);
    if (size < sizeof(struct fuse_trace_event)) {
        fprintf(stderr, "[BPF] Undersized event: %zu < %zu\n",
                size, sizeof(struct fuse_trace_event));
        return 0;
    }
    const struct fuse_trace_event* evt =
        static_cast<const struct fuse_trace_event*>(data);
    if (rbctx && rbctx->callback)
        rbctx->callback(*evt);
    return 0;
}

void BPFLoader::poll(EventCallback callback, std::atomic<bool>& running) {
    if (!loaded_ || !rb_) {
        fprintf(stderr, "[BPF] Cannot poll — not loaded\n");
        return;
    }
    RBContext* ctx = static_cast<RBContext*>(rb_ctx_);
    if (ctx) ctx->callback = std::move(callback);

    fprintf(stderr, "[BPF] Ring buffer poller started\n");
    while (running.load(std::memory_order_relaxed)) {
        int err = ring_buffer__poll(rb_, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[BPF] Ring buffer poll error: %d\n", err);
            break;
        }
    }
    fprintf(stderr, "[BPF] Ring buffer poller stopped\n");
}

void BPFLoader::close() {
    if (read_link_) {
        bpf_link__destroy(read_link_);
        read_link_ = nullptr;
    }
    if (write_link_) {
        bpf_link__destroy(write_link_);
        write_link_ = nullptr;
    }
    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }
    if (rb_ctx_) {
        delete static_cast<RBContext*>(rb_ctx_);
        rb_ctx_ = nullptr;
    }
    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
    loaded_ = false;
}

#else

BPFLoader::BPFLoader(const std::string& bpf_object_path)
    : bpf_object_path_(bpf_object_path) {
    fprintf(stderr, "[BPF] libbpf not available — stub loader\n");
}

BPFLoader::~BPFLoader() {}

bool BPFLoader::load_and_attach() {
    fprintf(stderr, "[BPF] libbpf not available — cannot load eBPF\n");
    return false;
}

void BPFLoader::poll(EventCallback, std::atomic<bool>&) {
    fprintf(stderr, "[BPF] libbpf not available — no polling\n");
}

void BPFLoader::close() {}
#endif

}
