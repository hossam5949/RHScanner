// ──────────────────────────────────────────────────────────────────────────────
//  scanner/scanner.cpp  —  M3 TCP probe, M4 threading, M5 service, M6 banner
// ──────────────────────────────────────────────────────────────────────────────

#include "scanner/scanner.h"
#include "threading/threading.h"
#include "service/service.h"
#include "os/os.h"

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

// ══════════════════════════════════════════════════════════════════════════════
//  ProbeEngine
// ══════════════════════════════════════════════════════════════════════════════

ProbeEngine::ProbeEngine(int timeoutMs, Logger& logger)
    : timeoutMs_(timeoutMs), logger_(logger)
{}

// ─────────────────────────────────────────────────────────────────────────────
//  tcpConnect  —  non-blocking connect + select() + SO_ERROR
//
//  SO_SNDTIMEO does not reliably interrupt blocking connect() on Linux.
//  The correct approach: O_NONBLOCK + connect() → EINPROGRESS → select().
// ─────────────────────────────────────────────────────────────────────────────
PortState ProbeEngine::tcpConnect(const std::string& ip, uint16_t port) const {
    logger_.debug("tcpConnect " + ip + ":" + std::to_string(port));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        logger_.warn("socket() failed: " + std::string(strerror(errno)));
        return PortState::Filtered;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd); return PortState::Filtered;
    }

    ::sockaddr_in addr{};
    if (!buildAddr(ip, port, addr)) { close(fd); return PortState::Filtered; }

    int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    if (rc == 0) {
        logger_.debug("  immediate connect: OPEN");
        close(fd); return PortState::Open;
    }

    if (errno != EINPROGRESS) {
        int err = errno; close(fd);
        if (err == ECONNREFUSED) { logger_.debug("  ECONNREFUSED: CLOSED"); return PortState::Closed; }
        logger_.debug("  errno=" + std::to_string(err) + ": FILTERED");
        return PortState::Filtered;
    }

    fd_set wset, eset;
    FD_ZERO(&wset); FD_SET(fd, &wset);
    FD_ZERO(&eset); FD_SET(fd, &eset);
    struct timeval tv{ timeoutMs_ / 1000, (timeoutMs_ % 1000) * 1000 };

    rc = select(fd + 1, nullptr, &wset, &eset, &tv);
    if (rc == 0) { close(fd); logger_.debug("  timeout: FILTERED"); return PortState::Filtered; }
    if (rc < 0)  { close(fd); return PortState::Filtered; }

    int sockErr = 0; socklen_t errLen = sizeof(sockErr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockErr, &errLen) < 0) {
        close(fd); return PortState::Filtered;
    }
    close(fd);

    if (sockErr == 0)            { logger_.debug("  SO_ERROR=0: OPEN");            return PortState::Open;     }
    if (sockErr == ECONNREFUSED) { logger_.debug("  SO_ERROR=ECONNREFUSED: CLOSED"); return PortState::Closed; }
    logger_.debug("  SO_ERROR=" + std::to_string(sockErr) + ": FILTERED");
    return PortState::Filtered;
}

// ─────────────────────────────────────────────────────────────────────────────
//  setSocketTimeout  —  SO_RCVTIMEO + SO_SNDTIMEO for blocking recv()/send()
// ─────────────────────────────────────────────────────────────────────────────
bool ProbeEngine::setSocketTimeout(int fd, int ms) const {
    struct timeval tv{ ms / 1000, (ms % 1000) * 1000 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) return false;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) return false;
    return true;
}

bool ProbeEngine::buildAddr(const std::string& ip, uint16_t port, ::sockaddr_in& out) {
    std::memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port   = htons(port);
    return inet_aton(ip.c_str(), &out.sin_addr) != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  icmpPing  —  stub; requires CAP_NET_RAW (M8 future milestone)
// ─────────────────────────────────────────────────────────────────────────────
int ProbeEngine::icmpPing(const std::string& ip) const {
    (void)ip;
    return -1;
}

// ─────────────────────────────────────────────────────────────────────────────
//  grabBanner  —  blocking connect + optional HTTP probe + recv()
//
//  Called only from postProcess() (single-threaded after all workers joined).
//  Uses a blocking socket with SO_RCVTIMEO — simpler than non-blocking here
//  because we have no progress loop to serve during this phase.
//
//  HTTP ports get a minimal HEAD request to trigger a response.
//  All other protocols (SSH, FTP, SMTP, POP3, IMAP) push a greeting first.
// ─────────────────────────────────────────────────────────────────────────────
std::string ProbeEngine::grabBanner(const std::string& ip, uint16_t port) const {
    logger_.debug("grabBanner " + ip + ":" + std::to_string(port));

    // TLS ports: we can connect but cannot read plaintext without a TLS
    // handshake — return empty rather than timing out.
    static const uint16_t TLS_PORTS[] = {443, 465, 636, 989, 990, 993, 995, 8443, 0};
    for (int i = 0; TLS_PORTS[i]; ++i)
        if (port == TLS_PORTS[i]) { logger_.debug("  TLS port - skipping banner"); return ""; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";

    setSocketTimeout(fd, timeoutMs_);

    ::sockaddr_in addr{};
    if (!buildAddr(ip, port, addr)) { close(fd); return ""; }

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd); return "";
    }

    // HTTP ports: send a HEAD request to get a response with Server: header
    static const uint16_t HTTP_PORTS[] = {
        80, 81, 8080, 8081, 8082, 8180, 8888,
        3000, 4848, 7474, 10000, 0
    };
    bool isHttp = false;
    for (int i = 0; HTTP_PORTS[i]; ++i)
        if (port == HTTP_PORTS[i]) { isHttp = true; break; }

    if (isHttp) {
        const char* req = "HEAD / HTTP/1.0\r\nHost: rhs\r\nConnection: close\r\n\r\n";
        if (send(fd, req, strlen(req), 0) <= 0) { close(fd); return ""; }
    }

    // Read up to 512 bytes
    char buf[513];
    ssize_t n = recv(fd, buf, 512, 0);
    close(fd);
    if (n <= 0) return "";

    buf[n] = '\0';
    std::string banner(buf, static_cast<size_t>(n));
    // Trim trailing whitespace
    while (!banner.empty() && (banner.back() == '\r' || banner.back() == '\n'
                                || banner.back() == ' '))
        banner.pop_back();
    logger_.debug("  banner (" + std::to_string(banner.size()) + " bytes): "
                  + banner.substr(0, 60));
    return banner;
}


// ══════════════════════════════════════════════════════════════════════════════
//  Scanner
// ══════════════════════════════════════════════════════════════════════════════

Scanner::Scanner(const ScanConfig& cfg, ResultStore& store, Logger& logger)
    : cfg_(cfg), store_(store), logger_(logger), probe_(cfg.timeoutMs, logger)
{}

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
//  run  —  parallel scan via ThreadPool (M4)
//
//  Workers call tcpConnect() and write to ResultStore.
//  Main thread polls completedCount() and prints progress to stderr.
//  postProcess() runs after all workers have joined — fully single-threaded.
// ─────────────────────────────────────────────────────────────────────────────
void Scanner::run() {
    auto tasks = buildTaskList();
    int  total = static_cast<int>(tasks.size());

    logger_.info("Starting scan: " + std::to_string(total) + " probe(s), "
                 + std::to_string(cfg_.numThreads) + " thread(s)");

    std::atomic<int> openFound{ 0 };

    auto handler = [this, &openFound](const ScanTask& task) {
        PortState state = probe_.tcpConnect(task.ip, task.port);
        ScanResult result(task.ip, task.port);
        result.state = state;
        store_.addResult(result);
        if (state == PortState::Open)
            openFound.fetch_add(1, std::memory_order_relaxed);
    };

    ThreadPool pool(cfg_.numThreads, handler, logger_);

    std::cerr << "  Progress: 0/" << total
              << "  [threads: " << cfg_.numThreads << "]" << std::flush;

    for (const auto& task : tasks) pool.submit(task);

    while (pool.completedCount() < total) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        std::cerr << "\r  Progress: " << pool.completedCount()
                  << "/" << total
                  << "  (open: " << openFound.load(std::memory_order_relaxed)
                  << ")  [threads: " << cfg_.numThreads << "]" << std::flush;
    }

    pool.waitAll();
    std::cerr << "\r" << std::string(70, ' ') << "\r" << std::flush;

    logger_.info("Scan complete: " + std::to_string(openFound.load())
                 + " open / " + std::to_string(total) + " probed");

    postProcess();
}

// ─────────────────────────────────────────────────────────────────────────────
//  postProcess  —  service + banner + version + OS detection (serial, M5/M6/M7)
//
//  Called after all workers have joined — no concurrent writes to store_.
//  Phase 1: port-mapping service name (M5)
//  Phase 2: banner grab + version parse (M6)
//  Phase 3: OS detection per unique IP (M7)
// ─────────────────────────────────────────────────────────────────────────────
void Scanner::postProcess() {
    auto results = store_.getResults();   // snapshot; safe after waitAll()

    // ── Phase 1 + 2: service name, banner, version ────────────────────────
    if (cfg_.doServiceDetect) {
        ServiceDetector detector(cfg_.timeoutMs);

        for (const ScanResult& r : results) {
            if (r.state != PortState::Open) continue;

            // Port-map name (M5) — always when -S is active
            std::string name = detector.identify(r.port);

            // Banner grab + version (M6) — when -S is active (doBannerGrab set)
            std::string banner, version;
            if (cfg_.doBannerGrab) {
                banner  = probe_.grabBanner(r.ip, r.port);
                version = detector.parseVersion(banner, name);
                logger_.debug("postProcess: " + r.ip + ":" + std::to_string(r.port)
                              + " svc=" + name + " ver=" + version);
            }

            store_.updateService(r.ip, r.port, name, version, banner);
        }

        // Refresh snapshot so OS phase sees the banner data
        results = store_.getResults();
    }

    // ── Phase 3: OS detection ─────────────────────────────────────────────
    if (cfg_.doOSDetect) {
        OSDetector osdet;
        osdet.registerStrategy(
            std::make_unique<BannerOSStrategy>());
        osdet.registerStrategy(
            std::make_unique<TTLFingerprintStrategy>(cfg_.timeoutMs, logger_));

        // Collect unique IPs that have at least one open port
        std::vector<std::string> uniqueIPs;
        for (const auto& r : results) {
            if (r.state != PortState::Open) continue;
            bool seen = false;
            for (const auto& ip : uniqueIPs) if (ip == r.ip) { seen = true; break; }
            if (!seen) uniqueIPs.push_back(r.ip);
        }

        for (const auto& ip : uniqueIPs) {
            OSGuess guess = osdet.detect(ip, results);
            logger_.debug("OS " + ip + ": " + OSDetector::guessToString(guess));

            if (guess.confidence > 0) {
                // Store the OS guess on the first open port for this IP
                for (const auto& r : results) {
                    if (r.ip == ip && r.state == PortState::Open) {
                        store_.updateOS(ip, r.port, guess);
                        break;
                    }
                }
            }
        }
    }
}

}  // namespace rhs
