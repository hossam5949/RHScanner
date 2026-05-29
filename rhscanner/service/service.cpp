// ──────────────────────────────────────────────────────────────────────────────
//  service/service.cpp
//
//  M1 skeleton — structural stubs only.
//  ServiceDatabase population:        M5
//  ServiceDetector identify():        M5
//  ServiceDetector grabBanner():      M5
//  ServiceDetector parseVersion():    M5
// ──────────────────────────────────────────────────────────────────────────────

#include "service/service.h"

namespace rhs {

// ═════════════════════════════════════════════════════════════════════════════
//  ServiceDatabase
// ═════════════════════════════════════════════════════════════════════════════

const ServiceDatabase& ServiceDatabase::instance() {
    static ServiceDatabase db;
    return db;
}

ServiceDatabase::ServiceDatabase() {
    // TODO (M5): populate map_ with 50+ well-known port/service pairs.
    //
    // Planned entries (sample):
    //   map_[21]    = "ftp";
    //   map_[22]    = "ssh";
    //   map_[23]    = "telnet";
    //   map_[25]    = "smtp";
    //   map_[53]    = "dns";
    //   map_[80]    = "http";
    //   map_[110]   = "pop3";
    //   map_[143]   = "imap";
    //   map_[443]   = "https";
    //   map_[445]   = "smb";
    //   map_[3306]  = "mysql";
    //   map_[3389]  = "rdp";
    //   map_[5432]  = "postgresql";
    //   map_[6379]  = "redis";
    //   map_[8080]  = "http-alt";
    //   map_[27017] = "mongodb";
}

std::string ServiceDatabase::lookup(uint16_t port) const {
    auto it = map_.find(port);
    return (it != map_.end()) ? it->second : "";
}

bool ServiceDatabase::known(uint16_t port) const {
    return map_.count(port) > 0;
}

// ═════════════════════════════════════════════════════════════════════════════
//  ServiceDetector
// ═════════════════════════════════════════════════════════════════════════════

ServiceDetector::ServiceDetector(int timeoutMs)
    : timeoutMs_(timeoutMs)
{}

std::string ServiceDetector::identify(uint16_t port) const {
    // TODO (M5): delegate to ServiceDatabase::lookup()
    (void)port;
    return "";
}

std::string ServiceDetector::grabBanner(const std::string& ip,
                                          uint16_t port) const {
    // TODO (M5): TCP connect + recv with timeout
    (void)ip; (void)port;
    return "";
}

std::string ServiceDetector::parseVersion(const std::string& banner,
                                           const std::string& service) const {
    // TODO (M5): dispatch to per-protocol parsers below
    (void)banner; (void)service;
    return "";
}

std::string ServiceDetector::parseSshVersion(const std::string& banner) const {
    // TODO (M5): "SSH-2.0-OpenSSH_8.9p1" → "OpenSSH 8.9p1"
    (void)banner;
    return "";
}

std::string ServiceDetector::parseHttpServer(const std::string& banner) const {
    // TODO (M5): "Server: Apache/2.4.54 (Debian)" → "Apache 2.4.54"
    (void)banner;
    return "";
}

std::string ServiceDetector::parseFtpBanner(const std::string& banner) const {
    // TODO (M5): "220 ProFTPD 1.3.7 ..." → "ProFTPD 1.3.7"
    (void)banner;
    return "";
}

std::string ServiceDetector::parseSmtpBanner(const std::string& banner) const {
    // TODO (M5): "220 mail.example.com ESMTP Postfix" → "Postfix"
    (void)banner;
    return "";
}

}  // namespace rhs
