// ──────────────────────────────────────────────────────────────────────────────
//  scanner/scanner.cpp
//
//  M1 skeleton — structural stubs only.
//  ProbeEngine socket logic:  M3
//  Scanner::run() with threading: M4
//  Scanner::postProcess():        M5 / M6
// ──────────────────────────────────────────────────────────────────────────────

#include "scanner/scanner.h"
#include "threading/threading.h"

#include <unistd.h>

#include <cstring>
#include <iostream>

namespace rhs {

// ═════════════════════════════════════════════════════════════════════════════
//  ProbeEngine
// ═════════════════════════════════════════════════════════════════════════════

ProbeEngine::ProbeEngine(int timeoutMs, Logger& logger)
    : timeoutMs_(timeoutMs)
    , logger_(logger)
{}

PortState ProbeEngine::tcpConnect(const std::string& ip, uint16_t port) const {
    // TODO (M3): create socket, set timeout, connect, interpret errno
    (void)ip; (void)port;
    return PortState::Unknown;
}

int ProbeEngine::icmpPing(const std::string& ip) const {
    // TODO (M6): raw ICMP socket, send echo, read TTL from reply
    (void)ip;
    return -1;
}

std::string ProbeEngine::grabBanner(const std::string& ip,
                                     uint16_t port) const {
    // TODO (M5): connect + recv first chunk within timeout
    (void)ip; (void)port;
    return "";
}

bool ProbeEngine::setSocketTimeout(int fd, int ms) const {
    // TODO (M3): setsockopt SO_RCVTIMEO / SO_SNDTIMEO
    (void)fd; (void)ms;
    return false;
}

bool ProbeEngine::buildAddr(const std::string& ip, uint16_t port,
                             ::sockaddr_in& out) {
    std::memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port   = htons(port);
    return inet_aton(ip.c_str(), &out.sin_addr) != 0;
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

void Scanner::run() {
    // TODO (M3): serial loop over tasks
    // TODO (M4): replace serial loop with ThreadPool
    // TODO (M5/M6): call postProcess() after probes complete
    logger_.info("Scanner::run() — not yet implemented (M3)");
    std::cout << "[Scanner::run() — stub]\n";
}

std::vector<ScanTask> Scanner::buildTaskList() const {
    // TODO (M3): cross-product of targetIPs x targetPorts
    return {};
}

void Scanner::postProcess() {
    // TODO (M5): iterate open results, call ServiceDetector
    // TODO (M6): call OSDetector per unique IP
}

}  // namespace rhs
