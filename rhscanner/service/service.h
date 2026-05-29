#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  service/service.h
//
//  ServiceDatabase — static, compile-time port → service-name mapping.
//  ServiceDetector — identifies services by port lookup and banner grabbing.
// ──────────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <string>
#include <unordered_map>

namespace rhs {

// ══════════════════════════════════════════════════════════════════════════════
//  ServiceDatabase  —  singleton, no file I/O, populated at startup
//
//  Contains well-known port assignments (IANA + common extras).
//  lookup() returns "" for unknown ports — never throws.
// ══════════════════════════════════════════════════════════════════════════════

class ServiceDatabase {
public:
    // Meyer's singleton — thread-safe under C++11.
    static const ServiceDatabase& instance();

    // Return the service name for a given port, or "" if unknown.
    std::string lookup(uint16_t port) const;

    // Return true if the port is in the database.
    bool known(uint16_t port) const;

private:
    ServiceDatabase();   // populates map_

    std::unordered_map<uint16_t, std::string> map_;
};

// ══════════════════════════════════════════════════════════════════════════════
//  ServiceDetector  —  per-port service identification
//
//  identify()    — pure lookup in ServiceDatabase
//  grabBanner()  — raw recv() after TCP connect (delegates to ProbeEngine)
//  parseVersion()— extract version string from a raw banner
// ══════════════════════════════════════════════════════════════════════════════

class ServiceDetector {
public:
    // timeoutMs is forwarded to the banner-grab socket timeout.
    explicit ServiceDetector(int timeoutMs = 1000);

    // Return the well-known service name for this port, or "".
    std::string identify(uint16_t port) const;

    // Connect to ip:port, read the server's opening bytes, return raw text.
    std::string grabBanner(const std::string& ip, uint16_t port) const;

    // Given a raw banner and the service name, attempt to extract a version.
    // Returns "" if no version pattern is recognised.
    std::string parseVersion(const std::string& banner,
                              const std::string& service) const;

private:
    // Per-protocol banner parsers — each returns a version string or "".
    std::string parseSshVersion(const std::string& banner)  const;
    std::string parseHttpServer(const std::string& banner)  const;
    std::string parseFtpBanner(const std::string& banner)   const;
    std::string parseSmtpBanner(const std::string& banner)  const;

    int timeoutMs_;
};

}  // namespace rhs
