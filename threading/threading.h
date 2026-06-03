#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  threading/threading.h
//
//  ThreadPool, WorkQueue, and ScanTask.
//
//  Design principles:
//    - WorkQueue is the only shared mutable state between producer and workers.
//    - All other coordination (result accumulation) goes through ResultStore.
//    - ScanTask is a pure value type — no pointers, no lifetime issues.
// ──────────────────────────────────────────────────────────────────────────────

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace rhs {

// Forward declarations from utils to avoid circular includes
class ResultStore;
class Logger;

// ══════════════════════════════════════════════════════════════════════════════
//  ScanTask  —  unit of work dispatched to the thread pool
// ══════════════════════════════════════════════════════════════════════════════

struct ScanTask {
    std::string ip;
    uint16_t    port        = 0;
    bool        doService   = false;  // run ServiceDetector for this task
    bool        doOS        = false;  // run OSDetector for this task
    bool        doBanner    = false;  // attempt banner grabbing
};

// ══════════════════════════════════════════════════════════════════════════════
//  WorkQueue  —  blocking FIFO that coordinates producer ↔ workers
// ══════════════════════════════════════════════════════════════════════════════

class WorkQueue {
public:
    WorkQueue() = default;

    // Push a task onto the queue. May be called from any thread.
    void push(ScanTask task);

    // Block until a task is available or the queue is marked done.
    // Returns false when the queue is drained and no more work is coming.
    bool pop(ScanTask& out);

    // Signal that no more tasks will be pushed. Unblocks all waiting pop()s.
    void setDone();

    bool   isDone() const;
    size_t size()  const;

private:
    std::queue<ScanTask>    queue_;
    mutable std::mutex      mutex_;
    std::condition_variable cv_;
    std::atomic<bool>       done_{ false };
};

// ══════════════════════════════════════════════════════════════════════════════
//  ThreadPool  —  fixed pool of N worker threads draining a WorkQueue
//
//  Usage:
//    ThreadPool pool(50, store, logger);
//    pool.submit(task);          // enqueue work
//    pool.waitAll();             // block until queue drained + all threads idle
//
//  Each worker thread runs a loop that:
//    1. Pops a ScanTask from the WorkQueue.
//    2. Calls ProbeEngine to test the port.
//    3. Optionally calls ServiceDetector and/or OSDetector.
//    4. Writes a ScanResult into ResultStore.
//
//  The callback function (workerFn_) is injected by Scanner so that
//  ThreadPool does not need to know about ProbeEngine directly.
// ══════════════════════════════════════════════════════════════════════════════

class ThreadPool {
public:
    using TaskHandler = std::function<void(const ScanTask&)>;

    // numThreads  — worker thread count
    // handler     — called once per ScanTask on a worker thread
    // logger      — for debug logging
    ThreadPool(int numThreads, TaskHandler handler, Logger& logger);

    ~ThreadPool();

    // Enqueue a task for execution. Non-blocking.
    void submit(ScanTask task);

    // Signal no more tasks, then join all worker threads.
    void waitAll();

    // Number of tasks completed so far (atomic, safe to poll from main thread).
    int completedCount() const;

private:
    void workerLoop();

    WorkQueue             queue_;
    TaskHandler           handler_;
    Logger&               logger_;
    std::vector<std::thread> workers_;
    std::atomic<int>      completed_{ 0 };
    std::atomic<bool>     started_{ false };
};

}  // namespace rhs
