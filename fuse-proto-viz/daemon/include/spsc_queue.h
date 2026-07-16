// ═══════════════════════════════════════════════════════════════════════
//  spsc_queue.h  —  Lock-Free Single-Producer / Single-Consumer Queue
//
//  Based on a bounded ring buffer with atomic indices. One thread
//  produces (the ring buffer poller) and one thread consumes (the
//  enrichment worker). No mutexes, no allocations on the hot path.
// ═══════════════════════════════════════════════════════════════════════

#pragma once

#include <atomic>
#include <cstddef>
#include <optional>
#include <memory>
#include <array>
#include <thread>

namespace fuseviz {

template <typename T, size_t Capacity>
class SPSCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0,
                  "Capacity must be a power of 2");

    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
    std::array<T, Capacity> buffer_;

    static constexpr size_t mask_ = Capacity - 1;

public:
    // Producer: push an element (call from ONE thread only)
    bool push(const T& item) {
        size_t tail = tail_.load(std::memory_order_relaxed);
        size_t next = (tail + 1) & mask_;
        if (next == head_.load(std::memory_order_acquire)) {
            return false; // full
        }
        buffer_[tail] = item;
        tail_.store(next, std::memory_order_release);
        return true;
    }

    bool push(T&& item) {
        size_t tail = tail_.load(std::memory_order_relaxed);
        size_t next = (tail + 1) & mask_;
        if (next == head_.load(std::memory_order_acquire)) {
            return false;
        }
        buffer_[tail] = std::move(item);
        tail_.store(next, std::memory_order_release);
        return true;
    }

    // Consumer: pop an element (call from ONE thread only)
    std::optional<T> pop() {
        size_t head = head_.load(std::memory_order_relaxed);
        if (head == tail_.load(std::memory_order_acquire)) {
            return std::nullopt; // empty
        }
        T item = std::move(buffer_[head]);
        head_.store((head + 1) & mask_, std::memory_order_release);
        return item;
    }

    bool empty() const {
        return head_.load(std::memory_order_acquire) ==
               tail_.load(std::memory_order_acquire);
    }

    size_t size() const {
        size_t tail = tail_.load(std::memory_order_acquire);
        size_t head = head_.load(std::memory_order_acquire);
        return (tail - head) & mask_;
    }
};

// Multi-producer / multi-consumer queue using a simple spinlock
// for the security engine's output (multiple workers → single consumer)
template <typename T, size_t Capacity>
class MPMCQueue {
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
    std::array<std::atomic<bool>, Capacity> ready_;
    std::array<T, Capacity> buffer_;
    static constexpr size_t mask_ = Capacity - 1;
    static_assert((Capacity & (Capacity - 1)) == 0, "Must be power of 2");

public:
    MPMCQueue() {
        for (auto& r : ready_) r.store(false, std::memory_order_relaxed);
    }

    bool push(const T& item) {
        for (;;) {
            size_t tail = tail_.load(std::memory_order_relaxed);
            size_t next = (tail + 1) & mask_;
            size_t head = head_.load(std::memory_order_acquire);
            if (next == head) return false; // full
            if (tail_.compare_exchange_weak(tail, next,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                buffer_[tail & mask_] = item;
                ready_[tail & mask_].store(true, std::memory_order_release);
                return true;
            }
            std::this_thread::yield();
        }
    }

    std::optional<T> pop() {
        size_t head = head_.load(std::memory_order_relaxed);
        if (!ready_[head & mask_].load(std::memory_order_acquire)) {
            return std::nullopt;
        }
        T item = std::move(buffer_[head & mask_]);
        ready_[head & mask_].store(false, std::memory_order_relaxed);
        head_.store((head + 1) & mask_, std::memory_order_release);
        return item;
    }
};

} // namespace fuseviz
