#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  scanner/scanner.h
//
//  Scanner  — top-level scan orchestrator.
//  ProbeEngine — low-level POSIX socket operations (stateless).
//
//  Dependency direction:
//    main → Scanner → ProbeEngine
//                   → ThreadPool  (threading/)
//                   → ServiceDetector (service/)
//                   → OSDetector      (os/)
//                   → ResultStore     (utils/)
// ──────────────────────────────────────────────────────────────────────────────

// POSIX socket headers must be included before the namespace so that
// sockaddr_in is visible as a global struct, not a forward-declared type
// inside rhs::.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "utils/utils.h"

#include <cstdint>
#include <string>

// Forward declaration — avoid including threading.h transitively in every TU
namespace rhs { class ThreadPool; }

namespace rhs {

// ══════════════════════════════════════════════════════════════════════════════
//  ProbeEngine  —  low-level socket operations
//
//  All methods are logically stateless given the same inputs — safe to call
//  concurrently from many threads without additional locking.
// ══════════════════════════════════════════════════════════════════════════════

class ProbeEngine {
public:
    // timeoutMs  — per-probe socket timeout in milliseconds
    // logger     — for debug-level socket logging
    ProbeEngine(int timeoutMs, Logger& logger);

    // Attempt a TCP connect to ip:port.
    // Returns Open, Closed, or Filtered based on errno / timing.
    PortState tcpConnect(const std::string& ip, uint16_t port) const;

    // Send an ICMP echo request and return the TTL from the reply.
    // Returns -1 if the host is unreachable or the probe times out.
    // Requires CAP_NET_RAW (run as root) for raw socket creation.
    int icmpPing(const std::string& ip) const;

    // Connect to ip:port and read the first chunk of data the server sends.
    // Returns the raw banner string, or "" if none arrives within timeout.
    std::string grabBanner(const std::string& ip, uint16_t port) const;

private:
    // Apply SO_RCVTIMEO / SO_SNDTIMEO to a socket fd. Returns false on error.
    bool setSocketTimeout(int fd, int ms) const;

    // Build a sockaddr_in for ip:port. ip must be a dotted-decimal string.
    // Returns false if inet_aton() fails (invalid IP).
    static bool buildAddr(const std::string& ip, uint16_t port,
                          ::sockaddr_in& out);

    int     timeoutMs_;
    Logger& logger_;
};

// ══════════════════════════════════════════════════════════════════════════════
//  Scanner  —  high-level scan orchestrator
//
//  Lifecycle:
//    Scanner s(cfg, store, logger);
//    s.run();   // blocks until all probes complete
//
//  run() builds the complete task list, feeds ThreadPool, polls progress,
//  then calls postProcess() to enrich results with service/OS data.
// ══════════════════════════════════════════════════════════════════════════════

class Scanner {
public:
    Scanner(const ScanConfig& cfg, ResultStore& store, Logger& logger);

    // Entry point — blocks until the scan completes.
    void run();

private:
    // Expand cfg_ into the flat list of ScanTask objects.
    std::vector<struct ScanTask> buildTaskList() const;

    // Called after all TCP probes finish.
    // Iterates open ports and runs ServiceDetector / OSDetector as configured.
    void postProcess();

    const ScanConfig& cfg_;
    ResultStore&      store_;
    Logger&           logger_;
    ProbeEngine       probe_;
};

}  // namespace rhs
