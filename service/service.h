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
// ══════════════════════════════════════════════════════════════════════════════

class ServiceDatabase {
public:
    static const ServiceDatabase& instance();
    std::string lookup(uint16_t port) const;
    bool        known(uint16_t port)  const;

private:
    ServiceDatabase();
    std::unordered_map<uint16_t, std::string> map_;
};

// ══════════════════════════════════════════════════════════════════════════════
//  ServiceDetector  —  per-port service identification + banner grabbing
// ══════════════════════════════════════════════════════════════════════════════

class ServiceDetector {
public:
    explicit ServiceDetector(int timeoutMs = 1000);

    // Return the well-known service name for this port, or "".
    std::string identify(uint16_t port) const;

    // Connect to ip:port, read the server greeting, return raw banner bytes.
    // Returns "" on timeout or connection error.
    std::string grabBanner(const std::string& ip, uint16_t port) const;

    // Given a raw banner and the service name, attempt to extract a version.
    // Returns "" if no version pattern is recognised.
    std::string parseVersion(const std::string& banner,
                              const std::string& service) const;

private:
    std::string parseSshVersion(const std::string& banner)  const;
    std::string parseHttpServer(const std::string& banner)  const;
    std::string parseFtpBanner(const std::string& banner)   const;
    std::string parseSmtpBanner(const std::string& banner)  const;
    std::string parsePop3Banner(const std::string& banner)  const;
    std::string parseImapBanner(const std::string& banner)  const;

    int timeoutMs_;
};

}  // namespace rhs
