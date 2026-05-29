// ──────────────────────────────────────────────────────────────────────────────
//  threading/threading.cpp
//
//  M1 skeleton — structural stubs only.
//  Full implementation arrives in M4 (ThreadPool + WorkQueue).
// ──────────────────────────────────────────────────────────────────────────────

#include "threading/threading.h"
#include "utils/utils.h"

#include <stdexcept>

namespace rhs {

// ═════════════════════════════════════════════════════════════════════════════
//  WorkQueue
// ═════════════════════════════════════════════════════════════════════════════

void WorkQueue::push(ScanTask task) {
    // TODO (M4): lock, push to queue_, notify one waiter
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(task));
    }
    cv_.notify_one();
}

bool WorkQueue::pop(ScanTask& out) {
    // TODO (M4): block until item available or done_ is set
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] {
        return !queue_.empty() || done_.load();
    });

    if (!queue_.empty()) {
        out = std::move(queue_.front());
        queue_.pop();
        return true;
    }
    return false;  // queue empty and done
}

void WorkQueue::setDone() {
    done_.store(true);
    cv_.notify_all();
}

bool WorkQueue::isDone() const {
    return done_.load();
}

size_t WorkQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

// ═════════════════════════════════════════════════════════════════════════════
//  ThreadPool
// ═════════════════════════════════════════════════════════════════════════════

ThreadPool::ThreadPool(int numThreads, TaskHandler handler, Logger& logger)
    : handler_(std::move(handler))
    , logger_(logger)
{
    // TODO (M4): validate numThreads, launch worker threads
    if (numThreads <= 0) {
        throw std::invalid_argument("ThreadPool: numThreads must be > 0");
    }

    workers_.reserve(static_cast<size_t>(numThreads));
    for (int i = 0; i < numThreads; ++i) {
        workers_.emplace_back([this] { workerLoop(); });
    }
    started_.store(true);
}

ThreadPool::~ThreadPool() {
    // Ensure clean shutdown even if waitAll() was not called.
    if (started_.load()) {
        queue_.setDone();
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
    }
}

void ThreadPool::submit(ScanTask task) {
    queue_.push(std::move(task));
}

void ThreadPool::waitAll() {
    // Signal no more work, then join all threads.
    queue_.setDone();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
}

int ThreadPool::completedCount() const {
    return completed_.load();
}

void ThreadPool::workerLoop() {
    ScanTask task;
    while (queue_.pop(task)) {
        // TODO (M4): call handler_(task), increment completed_
        try {
            handler_(task);
        } catch (const std::exception& e) {
            // Individual probe failures must not crash the worker.
            // TODO (M4): log properly via logger_
            (void)e;
        }
        completed_.fetch_add(1);
    }
}

}  // namespace rhs
