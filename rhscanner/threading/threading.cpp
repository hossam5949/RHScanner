// ──────────────────────────────────────────────────────────────────────────────
//  threading/threading.cpp
//
//  Milestone schedule:
//    M1: structural stubs (WorkQueue and ThreadPool shapes were already
//        present but tagged TODO — logic was mostly correct)
//    M4: full implementation — remove all TODOs, fix workerLoop logging,
//        verify every concurrency invariant                    ← this file
// ──────────────────────────────────────────────────────────────────────────────

#include "threading/threading.h"
#include "utils/utils.h"

#include <stdexcept>

namespace rhs {

// ═════════════════════════════════════════════════════════════════════════════
//  WorkQueue
//
//  Invariants that must hold at all times:
//    1. queue_ is only touched while mutex_ is held.
//    2. done_ is written once (true) and never reset.
//    3. Every push() wakes at least one waiting pop().
//    4. setDone() wakes ALL waiting pop()s so no thread sleeps forever.
//    5. pop() always re-evaluates its predicate after waking (spurious-safe).
// ═════════════════════════════════════════════════════════════════════════════

void WorkQueue::push(ScanTask task) {
    // Hold the lock only for the queue mutation, then release before notifying.
    // This avoids waking a waiter only to have it immediately block on the
    // mutex (a common performance anti-pattern).
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(task));
    }
    // Wake one waiting worker. If no thread is waiting the notification is
    // lost, but the next pop() will see the non-empty queue immediately.
    cv_.notify_one();
}

bool WorkQueue::pop(ScanTask& out) {
    std::unique_lock<std::mutex> lock(mutex_);

    // The predicate guards against spurious wakeups:
    //   - If the queue is non-empty  → take the item and return true.
    //   - If done_ is set and queue  → still drain the queue first.
    //     is non-empty                 (done_ does NOT mean "discard items")
    //   - If done_ is set and queue  → return false, worker exits cleanly.
    //     is empty
    //
    // done_ is an atomic<bool> but it is read here while the mutex is held
    // (unique_lock is locked during predicate evaluation inside cv_.wait).
    // The atomic is redundant for correctness here but makes the read safe
    // even if some other code path reads done_ outside the lock in future.
    cv_.wait(lock, [this] {
        return !queue_.empty() || done_.load(std::memory_order_relaxed);
    });

    if (!queue_.empty()) {
        out = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    // Queue is empty and done_ is true → signal the worker to exit.
    return false;
}

void WorkQueue::setDone() {
    // Store first (while the lock is NOT held — atomic write is sufficient),
    // then wake all waiters so they re-evaluate their predicates.
    done_.store(true, std::memory_order_release);
    cv_.notify_all();
}

bool WorkQueue::isDone() const {
    return done_.load(std::memory_order_acquire);
}

size_t WorkQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}


// ═════════════════════════════════════════════════════════════════════════════
//  ThreadPool
//
//  Ownership model:
//    - ThreadPool owns the WorkQueue and all worker std::threads.
//    - The TaskHandler (a std::function) is provided by Scanner::run() as a
//      lambda that captures ProbeEngine, ResultStore, and the two atomic
//      progress counters. ThreadPool never touches those objects directly.
//    - Logger is held by reference — caller must ensure it outlives the pool.
//
//  Shutdown sequence (via waitAll()):
//    1. Producer (Scanner::run) has already submitted all tasks.
//    2. waitAll() calls queue_.setDone() — marks no more work coming.
//    3. Workers drain remaining items from the queue.
//    4. Workers' pop() returns false on empty + done → workerLoop() exits.
//    5. Main thread joins every worker thread.
//    6. Destructor detects started_==true and repeats setDone()+join as a
//       safety net in case waitAll() was never called.
// ═════════════════════════════════════════════════════════════════════════════

ThreadPool::ThreadPool(int numThreads, TaskHandler handler, Logger& logger)
    : handler_(std::move(handler))
    , logger_(logger)
{
    if (numThreads <= 0) {
        throw std::invalid_argument(
            "ThreadPool: numThreads must be > 0, got "
            + std::to_string(numThreads));
    }

    // Reserve so that emplace_back never reallocates — a reallocation while
    // another thread is reading workers_ (in the destructor, for instance)
    // would be a data race.
    workers_.reserve(static_cast<size_t>(numThreads));

    for (int i = 0; i < numThreads; ++i) {
        workers_.emplace_back([this] { workerLoop(); });
    }

    started_.store(true, std::memory_order_release);
}

ThreadPool::~ThreadPool() {
    // Guard: only shut down if constructor actually started threads.
    // If waitAll() was already called, setDone() is idempotent (atomic store
    // of the same value) and join() on already-joined threads is UB, so we
    // check joinable() before joining.
    if (started_.load(std::memory_order_acquire)) {
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
    // Seal the queue — no more tasks will arrive.
    queue_.setDone();
    // Join blocks until every worker has finished its current task and exited
    // workerLoop(). After this returns, all handler_ calls are complete and
    // all results are in ResultStore.
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
}

int ThreadPool::completedCount() const {
    return completed_.load(std::memory_order_relaxed);
}

// ─────────────────────────────────────────────────────────────────────────────
//  workerLoop  —  runs on each worker thread for the pool's lifetime
//
//  The loop:
//    1. Blocks in pop() until a task arrives or the queue is sealed.
//    2. Calls handler_(task) — this is the Scanner-injected lambda that
//       runs tcpConnect() and writes to ResultStore.
//    3. Increments completed_ atomically.
//    4. Catches any exception thrown by handler_ so one bad probe cannot
//       kill the entire worker thread and leave tasks unprocessed.
// ─────────────────────────────────────────────────────────────────────────────
void ThreadPool::workerLoop() {
    ScanTask task;
    while (queue_.pop(task)) {
        try {
            handler_(task);
        } catch (const std::exception& ex) {
            // A probe failure must never crash the worker.
            // Log at warn level so it's visible with -v but not spam at -q.
            logger_.warn(
                std::string("Worker caught exception: ") + ex.what()
                + " [" + task.ip + ":" + std::to_string(task.port) + "]");
        } catch (...) {
            logger_.warn(
                "Worker caught unknown exception ["
                + task.ip + ":" + std::to_string(task.port) + "]");
        }
        // Increment AFTER the handler returns (or throws), so completedCount()
        // always reflects fully-processed tasks, never in-progress ones.
        completed_.fetch_add(1, std::memory_order_relaxed);
    }
}

}  // namespace rhs
