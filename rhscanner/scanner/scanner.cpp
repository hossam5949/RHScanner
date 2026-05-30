// ──────────────────────────────────────────────────────────────────────────────
//  scanner/scanner.cpp
//
//  Milestone schedule:
//    M1: structural stubs
//    M3: ProbeEngine::tcpConnect(), setSocketTimeout(), buildTaskList()
//    M4+M5: Scanner::run() ThreadPool parallel scan,
//           Scanner::postProcess() service detection       ← this
//    M6: ProbeEngine::icmpPing(), Scanner::postProcess() OS path
// ──────────────────────────────────────────────────────────────────────────────

#include "scanner/scanner.h"
#include "threading/threading.h"   // ScanTask definition
#include "service/service.h"        // ServiceDetector, ServiceDatabase

// POSIX socket / networking headers (already pulled in via scanner.h,
// but listed explicitly here for documentation clarity)
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

namespace rhs {

// ═════════════════════════════════════════════════════════════════════════════
//  ProbeEngine
// ═════════════════════════════════════════════════════════════════════════════

ProbeEngine::ProbeEngine(int timeoutMs, Logger& logger)
    : timeoutMs_(timeoutMs)
    , logger_(logger)
{}

// ─────────────────────────────────────────────────────────────────────────────
//  tcpConnect  —  non-blocking TCP connect with select()-based timeout
//
//  Why non-blocking + select() instead of SO_SNDTIMEO?
//  On Linux, SO_SNDTIMEO does NOT reliably interrupt a blocking connect() —
//  the kernel may ignore it entirely for connect(). The only portable, correct
//  approach is:
//    1. Set O_NONBLOCK on the socket.
//    2. Call connect() — returns immediately with EINPROGRESS.
//    3. select() on the write-fd-set with the desired timeout.
//    4. getsockopt(SOL_SOCKET, SO_ERROR) to read the actual connect result.
//    5. Map SO_ERROR → PortState.
//
//  PortState mapping:
//    SO_ERROR == 0            → Open     (connection established)
//    SO_ERROR == ECONNREFUSED → Closed   (target sent RST)
//    select() timeout         → Filtered (no response within timeoutMs)
//    EHOSTUNREACH/ENETUNREACH → Filtered (routing failure, no path)
//    ECONNRESET, EPERM, etc.  → Filtered (firewall drop or reset)
// ─────────────────────────────────────────────────────────────────────────────
PortState ProbeEngine::tcpConnect(const std::string& ip, uint16_t port) const {
    logger_.debug("tcpConnect " + ip + ":" + std::to_string(port));

    // ── 1. Create TCP socket ──────────────────────────────────────────────
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        logger_.warn("socket() failed for " + ip + ":" + std::to_string(port)
                     + " — " + strerror(errno));
        return PortState::Filtered;
    }

    // ── 2. Set O_NONBLOCK ─────────────────────────────────────────────────
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        logger_.warn("fcntl(O_NONBLOCK) failed: " + std::string(strerror(errno)));
        close(fd);
        return PortState::Filtered;
    }

    // ── 3. Build target address ───────────────────────────────────────────
    ::sockaddr_in addr{};
    if (!buildAddr(ip, port, addr)) {
        logger_.warn("buildAddr failed for '" + ip + "'");
        close(fd);
        return PortState::Filtered;
    }

    // ── 4. Initiate connect ───────────────────────────────────────────────
    int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    if (rc == 0) {
        // Immediate success — possible on loopback when listener is ready.
        logger_.debug("  immediate connect: OPEN");
        close(fd);
        return PortState::Open;
    }

    if (errno != EINPROGRESS) {
        // connect() failed before even starting — interpret errno directly.
        int err = errno;
        close(fd);
        if (err == ECONNREFUSED) {
            logger_.debug("  connect ECONNREFUSED: CLOSED");
            return PortState::Closed;
        }
        logger_.debug("  connect errno=" + std::to_string(err) + ": FILTERED");
        return PortState::Filtered;
    }

    // ── 5. Wait for connect to complete via select() ──────────────────────
    //
    // We monitor both the write set (successful connect) and the exceptional
    // set (some kernels signal errors there). In practice on Linux, errors
    // appear in the write set with SO_ERROR set, but monitoring both is
    // defensive and correct.
    fd_set wset, eset;
    FD_ZERO(&wset);  FD_SET(fd, &wset);
    FD_ZERO(&eset);  FD_SET(fd, &eset);

    struct timeval tv{};
    tv.tv_sec  = timeoutMs_ / 1000;
    tv.tv_usec = (timeoutMs_ % 1000) * 1000;

    rc = select(fd + 1, nullptr, &wset, &eset, &tv);

    if (rc == 0) {
        // Timeout — no RST received, port is firewalled or host unreachable.
        logger_.debug("  select() timeout: FILTERED");
        close(fd);
        return PortState::Filtered;
    }

    if (rc < 0) {
        logger_.warn("select() error: " + std::string(strerror(errno)));
        close(fd);
        return PortState::Filtered;
    }

    // ── 6. Read the actual connect result from SO_ERROR ───────────────────
    int         sockErr = 0;
    socklen_t   errLen  = sizeof(sockErr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockErr, &errLen) < 0) {
        logger_.warn("getsockopt(SO_ERROR) failed: " + std::string(strerror(errno)));
        close(fd);
        return PortState::Filtered;
    }

    close(fd);

    // ── 7. Map SO_ERROR → PortState ──────────────────────────────────────
    if (sockErr == 0) {
        logger_.debug("  SO_ERROR=0: OPEN");
        return PortState::Open;
    }
    if (sockErr == ECONNREFUSED) {
        logger_.debug("  SO_ERROR=ECONNREFUSED: CLOSED");
        return PortState::Closed;
    }

    // EHOSTUNREACH, ENETUNREACH, ETIMEDOUT, EACCES, EPERM → Filtered
    logger_.debug("  SO_ERROR=" + std::to_string(sockErr) + ": FILTERED");
    return PortState::Filtered;
}

// ─────────────────────────────────────────────────────────────────────────────
//  setSocketTimeout  —  applies SO_RCVTIMEO + SO_SNDTIMEO to a socket
//
//  Used by grabBanner() in M5 (recv() after connect needs a timeout).
//  NOT used by tcpConnect() — see the design note above.
// ─────────────────────────────────────────────────────────────────────────────
bool ProbeEngine::setSocketTimeout(int fd, int ms) const {
    struct timeval tv{};
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   &tv, sizeof(tv)) < 0) { return false; }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                   &tv, sizeof(tv)) < 0) { return false; }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  buildAddr  —  populate a sockaddr_in from a dotted-decimal string + port
// ─────────────────────────────────────────────────────────────────────────────
bool ProbeEngine::buildAddr(const std::string& ip, uint16_t port,
                             ::sockaddr_in& out) {
    std::memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port   = htons(port);
    return inet_aton(ip.c_str(), &out.sin_addr) != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  icmpPing  —  stub until M6 (raw socket + CAP_NET_RAW required)
// ─────────────────────────────────────────────────────────────────────────────
int ProbeEngine::icmpPing(const std::string& ip) const {
    // TODO (M6): raw ICMP echo — requires root / CAP_NET_RAW
    (void)ip;
    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
//  grabBanner  —  stub until M5 (recv() after TCP connect)
// ─────────────────────────────────────────────────────────────────────────────
std::string ProbeEngine::grabBanner(const std::string& ip,
                                     uint16_t port) const {
    // TODO (M5): connect, set SO_RCVTIMEO via setSocketTimeout(), recv()
    (void)ip; (void)port;
    return "";
}


// ═════════════════════════════════════════════════════════════════════════════
//  Scanner
// ═════════════════════════════════════════════════════════════════════════════

Scanner::Scanner(const ScanConfig& cfg, ResultStore& store, Logger& logger)
    : cfg_(cfg)
    , store_(store)
    , logger_(logger)
    , probe_(cfg.timeoutMs, logger)
{}

// ─────────────────────────────────────────────────────────────────────────────
//  buildTaskList  —  cross-product of targetIPs × targetPorts
//
//  Outer loop: IPs.  Inner loop: ports.
//  This groups all ports for a given host together — the same order Nmap uses —
//  which makes output easier to read and is cache-friendly for TCP state.
// ─────────────────────────────────────────────────────────────────────────────
std::vector<ScanTask> Scanner::buildTaskList() const {
    std::vector<ScanTask> tasks;
    tasks.reserve(cfg_.targetIPs.size() * cfg_.targetPorts.size());

    for (const auto& ip : cfg_.targetIPs) {
        for (uint16_t port : cfg_.targetPorts) {
            ScanTask t;
            t.ip        = ip;
            t.port      = port;
            t.doService = cfg_.doServiceDetect;
            t.doOS      = cfg_.doOSDetect;
            t.doBanner  = cfg_.doBannerGrab;
            tasks.push_back(std::move(t));
        }
    }
    return tasks;
}

// ─────────────────────────────────────────────────────────────────────────────
//  run  —  parallel scan using ThreadPool  (M4)
//
//  Architecture:
//    - Main thread builds the task list and submits every ScanTask to
//      the ThreadPool in one tight loop (submit() is non-blocking).
//    - N worker threads drain the WorkQueue concurrently, each calling
//      probe_.tcpConnect() independently. ProbeEngine is stateless so
//      concurrent calls are safe with no additional locking.
//    - Each worker writes its ScanResult to ResultStore via addResult(),
//      which holds its own mutex — the only contended lock in the hot path.
//    - Two atomics track progress: completed_ (inside ThreadPool) counts
//      fully-processed tasks; openFound_ is incremented by workers on OPEN.
//    - The main thread prints the progress line by polling the atomics in a
//      sleep loop. It is the ONLY thread that writes to stderr during the
//      scan, eliminating all output-interleaving races.
//    - waitAll() seals the queue and joins every worker before returning.
//    - postProcess() runs after all workers have exited — safe to read
//      ResultStore without locking.
//
//  Thread-safety summary:
//    ProbeEngine::tcpConnect()  — stateless, no shared state, fully safe.
//    ResultStore::addResult()   — mutex-guarded, safe from N threads.
//    Logger                     — mutex-guarded, safe from N threads.
//    openFound_ / completed_    — std::atomic, safe from N threads.
//    stderr progress line       — written ONLY by main thread, no race.
// ─────────────────────────────────────────────────────────────────────────────
void Scanner::run() {
    auto tasks = buildTaskList();
    int  total = static_cast<int>(tasks.size());

    logger_.info("Starting threaded scan: "
                 + std::to_string(total) + " probe(s), "
                 + std::to_string(cfg_.numThreads) + " thread(s)");

    // ── Atomic progress counters ──────────────────────────────────────────
    // Workers increment these; the main thread reads them for display.
    // memory_order_relaxed is sufficient: we only need the final values
    // to be correct after waitAll() (which provides the necessary barrier
    // via thread join — join establishes a happens-before relationship).
    std::atomic<int> openFound{ 0 };

    // ── Task handler lambda ───────────────────────────────────────────────
    // Injected into ThreadPool — called once per ScanTask on a worker thread.
    // Captures by reference: probe_, store_, openFound are all thread-safe.
    // ScanTask is passed by const-ref (value copy lives in the WorkQueue).
    auto handler = [this, &openFound](const ScanTask& task) {
        PortState state = probe_.tcpConnect(task.ip, task.port);

        ScanResult result(task.ip, task.port);
        result.state = state;
        store_.addResult(result);

        if (state == PortState::Open) {
            openFound.fetch_add(1, std::memory_order_relaxed);
        }
    };

    // ── Construct pool and submit all tasks ───────────────────────────────
    // ThreadPool constructor launches cfg_.numThreads worker threads
    // immediately. Workers start blocking in WorkQueue::pop() right away.
    // submit() is non-blocking — it enqueues and returns. The producer
    // loop here completes long before all workers finish their probes.
    ThreadPool pool(cfg_.numThreads, handler, logger_);

    // Print the initial progress line before any task runs.
    std::cerr << "  Progress: 0/" << total
              << "  [threads: " << cfg_.numThreads << "]"
              << std::flush;

    for (const auto& task : tasks) {
        pool.submit(task);
    }

    // ── Progress polling loop ─────────────────────────────────────────────
    // After all tasks are submitted, poll completedCount() until every task
    // is done, refreshing the progress display each iteration.
    //
    // sleep_for(5ms) keeps CPU at ~0% while workers are blocked on connect()
    // timeouts. The final waitAll() handles the case where all tasks finish
    // between the loop condition check and waitAll().
    //
    // We do NOT call waitAll() inside the loop — that would seal the queue
    // prematurely. Instead: submit all → poll progress → waitAll().
    while (pool.completedCount() < total) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        std::cerr << "\r  Progress: " << pool.completedCount()
                  << "/" << total
                  << "  (open: " << openFound.load(std::memory_order_relaxed)
                  << ")  [threads: " << cfg_.numThreads << "]"
                  << std::flush;
    }

    // Seal queue, join all worker threads. After this line, all handler
    // calls are complete and ResultStore contains every result.
    pool.waitAll();

    // Clear the progress line cleanly before the result table prints.
    std::cerr << "\r" << std::string(60, ' ') << "\r" << std::flush;

    logger_.info("Scan complete: "
                 + std::to_string(openFound.load()) + " open / "
                 + std::to_string(total) + " probed");

    // postProcess() is a no-op until M5/M6.
    postProcess();
}

// ─────────────────────────────────────────────────────────────────────────────
//  postProcess  —  enrich open results with service data  (M4+M5)
//
//  Called after waitAll() — all worker threads have joined, so ResultStore
//  can be read without locking (no concurrent writers exist at this point).
//  We still call updateService() through the store's mutex for correctness
//  and to keep the invariant that all ResultStore writes are lock-guarded.
//
//  Service detection is port-mapping only in this milestone — O(1) lookup
//  in ServiceDatabase, no network I/O.  Banner grabbing and version parsing
//  are added in a later milestone.
//
//  OS detection (M6): added here as a TODO once OSDetector is implemented.
// ─────────────────────────────────────────────────────────────────────────────
void Scanner::postProcess() {
    if (!cfg_.doServiceDetect) { return; }

    ServiceDetector detector(cfg_.timeoutMs);

    // getResults() returns a snapshot copy — safe to iterate without holding
    // the store mutex.  updateService() acquires the mutex internally for
    // each write.
    for (const ScanResult& r : store_.getResults()) {
        if (r.state != PortState::Open) { continue; }

        std::string name = detector.identify(r.port);
        if (!name.empty()) {
            logger_.debug("postProcess: " + r.ip + ":" +
                          std::to_string(r.port) + " -> " + name);
            store_.updateService(r.ip, r.port, name, "");
        }
    }

    // TODO (M6): for each unique IP with Open ports, call OSDetector
}

}  // namespace rhs
