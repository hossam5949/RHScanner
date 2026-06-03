// ──────────────────────────────────────────────────────────────────────────────
//  utils/utils.cpp  —  complete implementation (M2–M7)
// ──────────────────────────────────────────────────────────────────────────────

#include "utils/utils.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace rhs {

// ─────────────────────────────────────────────────────────────────────────────
//  ANSI colour constants  (translation-unit private)
//  All output functions check isTTY() before emitting these.
// ─────────────────────────────────────────────────────────────────────────────
namespace ansi {
    static const char* RESET  = "\033[0m";
    static const char* PINK   = "\033[38;5;213m";
    static const char* BLUE   = "\033[38;5;75m";
    static const char* RED    = "\033[31m";
    static const char* GREEN  = "\033[32m";
    static const char* YELLOW = "\033[33m";
    static const char* BOLD   = "\033[1m";
    static const char* DIM    = "\033[2m";
    static const char* CYAN   = "\033[36m";
    static const char* WHITE  = "\033[37m";
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal string helpers  (TU-private)
// ─────────────────────────────────────────────────────────────────────────────
namespace {

std::vector<std::string> splitString(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim)) parts.push_back(token);
    if (parts.empty()) parts.push_back("");
    return parts;
}

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    auto start = s.find_first_not_of(ws);
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(ws);
    return s.substr(start, end - start + 1);
}

bool parseUInt(const std::string& s, unsigned long& out) {
    if (s.empty()) return false;
    for (char c : s) { if (c < '0' || c > '9') return false; }
    try { out = std::stoul(s); return true; }
    catch (...) { return false; }
}

}  // anonymous namespace


// ══════════════════════════════════════════════════════════════════════════════
//  HostResolver
// ══════════════════════════════════════════════════════════════════════════════

bool HostResolver::isIPv4(const std::string& s) {
    struct in_addr addr{};
    return inet_aton(s.c_str(), &addr) != 0;
}

std::vector<std::string> HostResolver::resolve(const std::string& hostname) {
    std::vector<std::string> results;

    struct addrinfo hints{};
    hints.ai_family   = AF_INET;        // IPv4 only
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (rc != 0 || res == nullptr) return results;

    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        auto* sa = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) {
            std::string ip(buf);
            // Deduplicate
            if (std::find(results.begin(), results.end(), ip) == results.end()) {
                results.push_back(ip);
            }
        }
    }

    freeaddrinfo(res);
    return results;
}


// ══════════════════════════════════════════════════════════════════════════════
//  IPRange
// ══════════════════════════════════════════════════════════════════════════════

IPRange::IPRange(const std::string& expr) : expr_(trim(expr)) {
    if (expr_.empty()) { errorMsg_ = "IP expression is empty"; return; }

    if (expr_.find('/') != std::string::npos) {
        // CIDR: "192.168.1.0/24"
        auto slashPos       = expr_.find('/');
        std::string ipPart  = expr_.substr(0, slashPos);
        std::string pfxPart = expr_.substr(slashPos + 1);
        if (!isValidIPv4(ipPart)) {
            errorMsg_ = "Invalid IP in CIDR: '" + ipPart + "'"; return;
        }
        unsigned long prefix = 0;
        if (!parseUInt(pfxPart, prefix) || prefix > 32) {
            errorMsg_ = "Invalid CIDR prefix: '" + pfxPart + "' (must be 0-32)"; return;
        }
        parseCIDR(ipPart, static_cast<int>(prefix));

    } else if (expr_.find('-') != std::string::npos) {
        // Last-octet range: "192.168.1.1-20"
        auto lastDot = expr_.rfind('.');
        if (lastDot == std::string::npos) {
            errorMsg_ = "Invalid range: '" + expr_ + "' (expected a.b.c.lo-hi)"; return;
        }
        std::string base      = expr_.substr(0, lastDot);
        std::string rangePart = expr_.substr(lastDot + 1);
        auto dashPos          = rangePart.find('-');
        if (dashPos == std::string::npos) { parseSingle(expr_); return; }

        std::string loPart = rangePart.substr(0, dashPos);
        std::string hiPart = rangePart.substr(dashPos + 1);
        unsigned long lo = 0, hi = 0;
        if (!parseUInt(loPart, lo) || lo > 255) {
            errorMsg_ = "Invalid range start '" + loPart + "'"; return;
        }
        if (!parseUInt(hiPart, hi) || hi > 255) {
            errorMsg_ = "Invalid range end '" + hiPart + "'"; return;
        }
        if (lo > hi) {
            errorMsg_ = "Range start (" + loPart + ") > end (" + hiPart + ")"; return;
        }
        if (!isValidIPv4(base + ".0")) {
            errorMsg_ = "Invalid base address '" + base + "'"; return;
        }
        parseLastOctetRange(base, static_cast<int>(lo), static_cast<int>(hi));

    } else if (isValidIPv4(expr_)) {
        // Plain IPv4 address
        parseSingle(expr_);

    } else {
        // Attempt hostname resolution
        resolveHostname(expr_);
    }
}

std::vector<std::string> IPRange::expand()    const { return expanded_; }
bool                     IPRange::isValid()   const { return valid_; }
const std::string&       IPRange::errorMsg()  const { return errorMsg_; }

void IPRange::parseSingle(const std::string& ip) {
    if (!isValidIPv4(ip)) { errorMsg_ = "Invalid IPv4: '" + ip + "'"; return; }
    expanded_.push_back(ip);
    valid_ = true;
}

void IPRange::resolveHostname(const std::string& hostname) {
    auto ips = HostResolver::resolve(hostname);
    if (ips.empty()) {
        errorMsg_ = "Could not resolve hostname '" + hostname + "'";
        return;
    }
    expanded_ = std::move(ips);
    valid_ = true;
}

void IPRange::parseLastOctetRange(const std::string& base, int lo, int hi) {
    expanded_.reserve(static_cast<size_t>(hi - lo + 1));
    for (int octet = lo; octet <= hi; ++octet)
        expanded_.push_back(base + "." + std::to_string(octet));
    valid_ = true;
}

void IPRange::parseCIDR(const std::string& ip, int prefix) {
    struct in_addr addr{};
    inet_aton(ip.c_str(), &addr);
    uint32_t network  = ntohl(addr.s_addr);
    uint32_t hostBits = static_cast<uint32_t>(32 - prefix);
    uint32_t hostMask = (hostBits == 32) ? 0xFFFFFFFFu : ((1u << hostBits) - 1u);
    uint32_t base     = network & ~hostMask;

    uint32_t first, last;
    if (prefix >= 31) { first = base; last = base | hostMask; }
    else              { first = base + 1; last = (base | hostMask) - 1; }
    if (first > last) { first = base; last = base; }

    expanded_.reserve(static_cast<size_t>(last - first + 1));
    for (uint32_t host = first; host <= last; ++host) {
        struct in_addr a{};
        a.s_addr = htonl(host);
        expanded_.push_back(std::string(inet_ntoa(a)));
    }
    valid_ = true;
}

bool IPRange::isValidIPv4(const std::string& ip) {
    auto parts = splitString(ip, '.');
    if (parts.size() != 4) return false;
    for (const auto& part : parts) {
        if (part.empty() || part.size() > 3) return false;
        unsigned long val = 0;
        if (!parseUInt(part, val) || val > 255) return false;
        if (part.size() > 1 && part[0] == '0') return false;
    }
    return true;
}


// ══════════════════════════════════════════════════════════════════════════════
//  PortRange
// ══════════════════════════════════════════════════════════════════════════════

PortRange::PortRange(const std::string& expr) : expr_(trim(expr)) {
    auto seen = std::make_unique<bool[]>(65536);
    std::fill(seen.get(), seen.get() + 65536, false);

    auto addPort = [&](uint16_t p) {
        if (!seen[p]) { seen[p] = true; expanded_.push_back(p); }
    };
    auto addRange = [&](uint16_t lo, uint16_t hi) {
        expanded_.reserve(expanded_.size() + static_cast<size_t>(hi - lo + 1));
        for (int p = static_cast<int>(lo); p <= static_cast<int>(hi); ++p) {
            auto u = static_cast<uint16_t>(p);
            if (!seen[u]) { seen[u] = true; expanded_.push_back(u); }
        }
        valid_ = true;
    };

    if (expr_.empty()) { addRange(1, 1024); return; }

    if (expr_.find(',') != std::string::npos) {
        parseCSV(expr_, seen.get()); return;
    }

    if (expr_.find('-') != std::string::npos) {
        auto dashPos   = expr_.find('-');
        std::string lo = expr_.substr(0, dashPos);
        std::string hi = expr_.substr(dashPos + 1);
        unsigned long lv = 0, hv = 0;
        if (!parseUInt(lo, lv) || lv == 0 || lv > 65535) {
            errorMsg_ = "Invalid port range start '" + lo + "' (must be 1-65535)"; return;
        }
        if (!parseUInt(hi, hv) || hv == 0 || hv > 65535) {
            errorMsg_ = "Invalid port range end '" + hi + "' (must be 1-65535)"; return;
        }
        if (lv > hv) {
            errorMsg_ = "Port range start (" + lo + ") > end (" + hi + ")"; return;
        }
        addRange(static_cast<uint16_t>(lv), static_cast<uint16_t>(hv));
        return;
    }

    unsigned long val = 0;
    if (!parseUInt(expr_, val) || val == 0 || val > 65535) {
        errorMsg_ = "Invalid port '" + expr_ + "' (must be 1-65535)"; return;
    }
    addPort(static_cast<uint16_t>(val));
    valid_ = true;
}

std::vector<uint16_t> PortRange::expand()   const { return expanded_; }
bool                  PortRange::isValid()  const { return valid_; }
const std::string&    PortRange::errorMsg() const { return errorMsg_; }

void PortRange::parseSingle(uint16_t port) {
    expanded_.push_back(port);
    valid_ = true;
}

void PortRange::parseRange(uint16_t lo, uint16_t hi) {
    expanded_.reserve(expanded_.size() + static_cast<size_t>(hi - lo + 1));
    for (int p = static_cast<int>(lo); p <= static_cast<int>(hi); ++p)
        expanded_.push_back(static_cast<uint16_t>(p));
    valid_ = true;
}

void PortRange::parseCSV(const std::string& csv, bool seen[]) {
    for (const auto& raw : splitString(csv, ',')) {
        std::string token = trim(raw);
        if (token.empty()) {
            errorMsg_ = "Empty token in port list '" + csv + "'";
            valid_ = false; expanded_.clear(); return;
        }
        if (token.find('-') != std::string::npos) {
            auto dp = token.find('-');
            std::string lo = token.substr(0, dp), hi = token.substr(dp + 1);
            unsigned long lv = 0, hv = 0;
            if (!parseUInt(lo, lv) || lv == 0 || lv > 65535) {
                errorMsg_ = "Invalid port '" + lo + "' in list"; valid_ = false; expanded_.clear(); return;
            }
            if (!parseUInt(hi, hv) || hv == 0 || hv > 65535) {
                errorMsg_ = "Invalid port '" + hi + "' in list"; valid_ = false; expanded_.clear(); return;
            }
            if (lv > hv) {
                errorMsg_ = "Port range start > end in list"; valid_ = false; expanded_.clear(); return;
            }
            expanded_.reserve(expanded_.size() + static_cast<size_t>(hv - lv + 1));
            for (int p = static_cast<int>(lv); p <= static_cast<int>(hv); ++p) {
                uint16_t u = static_cast<uint16_t>(p);
                if (!seen[u]) { seen[u] = true; expanded_.push_back(u); }
            }
        } else {
            unsigned long val = 0;
            if (!parseUInt(token, val) || val == 0 || val > 65535) {
                errorMsg_ = "Invalid port '" + token + "' (must be 1-65535)";
                valid_ = false; expanded_.clear(); return;
            }
            uint16_t p = static_cast<uint16_t>(val);
            if (!seen[p]) { seen[p] = true; expanded_.push_back(p); }
        }
    }
    if (!expanded_.empty()) valid_ = true;
}


// ══════════════════════════════════════════════════════════════════════════════
//  ResultStore
// ══════════════════════════════════════════════════════════════════════════════

void ResultStore::addResult(const ScanResult& result) {
    std::lock_guard<std::mutex> lock(mutex_);
    Key k{ result.ip, result.port };
    results_[k] = result;
}

std::vector<ScanResult> ResultStore::getResults() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ScanResult> out;
    out.reserve(results_.size());
    for (const auto& kv : results_) out.push_back(kv.second);
    return out;
}

void ResultStore::updateService(const std::string& ip, uint16_t port,
                                const std::string& name,
                                const std::string& version,
                                const std::string& banner) {
    std::lock_guard<std::mutex> lock(mutex_);
    Key k{ ip, port };
    auto it = results_.find(k);
    if (it != results_.end()) {
        if (!name.empty())    it->second.serviceName    = name;
        if (!version.empty()) it->second.serviceVersion = version;
        if (!banner.empty())  { it->second.rawBanner = banner; it->second.bannerGrabbed = true; }
    }
}

void ResultStore::updateOS(const std::string& ip, uint16_t port,
                           const OSGuess& guess) {
    std::lock_guard<std::mutex> lock(mutex_);
    Key k{ ip, port };
    auto it = results_.find(k);
    if (it != results_.end()) {
        it->second.osGuess = guess;
    }
}

std::size_t ResultStore::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return results_.size();
}


// ══════════════════════════════════════════════════════════════════════════════
//  Logger
// ══════════════════════════════════════════════════════════════════════════════

Logger::Logger(int verbosityLevel)
    : level_(static_cast<Level>(verbosityLevel))
{}

void Logger::debug(const std::string& msg) const {
    if (level_ >= Level::Debug) log("[DBG]", msg);
}
void Logger::info(const std::string& msg) const {
    if (level_ >= Level::Info) log("[INF]", msg);
}
void Logger::warn(const std::string& msg)  const { log("[WRN]", msg); }
void Logger::error(const std::string& msg) const { log("[ERR]", msg); }

void Logger::log(const std::string& prefix, const std::string& msg) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cerr << prefix << " " << msg << "\n";
}


// ══════════════════════════════════════════════════════════════════════════════
//  OutputFormatter
// ══════════════════════════════════════════════════════════════════════════════

OutputFormatter::OutputFormatter(int verbosity) : verbosity_(verbosity) {}

bool OutputFormatter::isTTY() {
    return isatty(STDOUT_FILENO) != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  printBanner  —  large ASCII-art RH logo
//
//  The R is rendered in pink (ANSI 213) and H in blue (ANSI 75).
//  Colours are suppressed when stdout is not a TTY.
// ─────────────────────────────────────────────────────────────────────────────
void OutputFormatter::printBanner() const {
    const bool colour = isTTY();
    const std::string P  = colour ? ansi::PINK  : "";
    const std::string B  = colour ? ansi::BLUE  : "";
    const std::string RS = colour ? ansi::RESET : "";
    const std::string BD = colour ? ansi::BOLD  : "";
    const std::string DM = colour ? ansi::DIM   : "";
    const std::string CY = colour ? ansi::CYAN  : "";
    const std::string WH = colour ? ansi::WHITE : "";

    std::cout << "\n";

    // Row 0
    std::cout << "  "
              << P  << BD << "██████╗ " << RS
              << B  << BD << "██╗  ██╗" << RS << "\n";
    // Row 1
    std::cout << "  "
              << P  << BD << "██╔══██╗" << RS
              << B  << BD << "██║  ██║" << RS << "\n";
    // Row 2
    std::cout << "  "
              << P  << BD << "██████╔╝" << RS
              << B  << BD << "███████║" << RS << "\n";
    // Row 3
    std::cout << "  "
              << P  << BD << "██╔══██╗" << RS
              << B  << BD << "██╔══██║" << RS << "\n";
    // Row 4
    std::cout << "  "
              << P  << BD << "██║  ██║" << RS
              << B  << BD << "██║  ██║" << RS << "\n";
    // Row 5
    std::cout << "  "
              << P  << BD << "╚═╝  ╚═╝" << RS
              << B  << BD << "╚═╝  ╚═╝" << RS << "\n";

    std::cout << "\n";
    std::cout << "  " << WH << BD << "Scanner" << RS
              << "  " << DM << "v0.1.0" << RS << "\n";
    std::cout << "  " << DM << "Made by Hossam Elsemelawy" << RS << "\n";
    std::cout << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  printHelp
// ─────────────────────────────────────────────────────────────────────────────
void OutputFormatter::printHelp() {
    std::cout
        << "\n"
        << ansi::BOLD << "  Usage:" << ansi::RESET
        << "  rhscanner [OPTIONS]\n\n"

        << ansi::BOLD << ansi::CYAN << "  Target\n" << ansi::RESET
        << "    " << ansi::BOLD << "-H"  << ansi::RESET
        << " <host>          Single IP, CIDR, range, or hostname\n"
        << "                      "
        << ansi::DIM
        << "192.168.1.10  |  192.168.1.0/24  |  192.168.1.1-20  |  example.com\n"
        << ansi::RESET
        << "    " << ansi::BOLD << "-RH" << ansi::RESET
        << " <host>         Full recon mode  (implies -P -S -O)\n\n"

        << ansi::BOLD << ansi::CYAN << "  Scan types\n" << ansi::RESET
        << "    " << ansi::BOLD << "-P" << ansi::RESET
        << " [range]         Port scan  (default 1-1024 if no range given)\n"
        << "                      "
        << ansi::DIM << "-P  |  -P 80  |  -P 1-65535  |  -P 22,80,443\n"
        << ansi::RESET
        << "    " << ansi::BOLD << "-S" << ansi::RESET
        << "                   Service + banner + version detection\n"
        << "    " << ansi::BOLD << "-O" << ansi::RESET
        << "                   OS detection (passive banner analysis)\n\n"

        << ansi::BOLD << ansi::CYAN << "  Performance\n" << ansi::RESET
        << "    " << ansi::BOLD << "-T" << ansi::RESET
        << " <n>              Thread count  (default: 50, max: 500)\n"
        << "    " << ansi::BOLD << "--timeout" << ansi::RESET
        << " <ms>      Per-probe socket timeout  (default: 1000 ms)\n\n"

        << ansi::BOLD << ansi::CYAN << "  Output\n" << ansi::RESET
        << "    " << ansi::BOLD << "-v" << ansi::RESET
        << "                   Verbose: also show closed/filtered ports\n"
        << "    " << ansi::BOLD << "-vv" << ansi::RESET
        << "                  Debug: log every socket operation\n\n"

        << ansi::BOLD << ansi::CYAN << "  Misc\n" << ansi::RESET
        << "    " << ansi::BOLD << "-h, --help" << ansi::RESET
        << "          This screen\n"
        << "    " << ansi::BOLD << "--version" << ansi::RESET
        << "           Print version string\n\n"

        << ansi::BOLD << ansi::CYAN << "  Examples\n" << ansi::RESET
        << "    rhscanner -H 192.168.1.10 -P\n"
        << "    rhscanner -H 192.168.1.10 -P 1-1024 -S\n"
        << "    rhscanner -H 192.168.1.10 -P 80,443 -S -O\n"
        << "    rhscanner -H 192.168.1.1-50 -P 22 -T 100\n"
        << "    rhscanner -H scanme.nmap.org -P 22,80 -S -O\n"
        << "    rhscanner -RH 192.168.1.10\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  printResults  —  columnar table with VERSION + per-IP OS block
// ─────────────────────────────────────────────────────────────────────────────
void OutputFormatter::printResults(const std::vector<ScanResult>& results) const {
    const bool colour = isTTY();

    // Filter by verbosity
    std::vector<const ScanResult*> rows;
    rows.reserve(results.size());
    for (const auto& r : results) {
        if (verbosity_ >= 1 || r.state == PortState::Open)
            rows.push_back(&r);
    }

    if (rows.empty()) {
        std::cout << "  No open ports found.\n\n";
        return;
    }

    // ── Column widths ──────────────────────────────────────────────────────
    const int W_IP      = 18;
    const int W_PORT    = 7;
    const int W_STATE   = 10;
    const int W_SERVICE = 14;
    const int W_VERSION = 26;

    // ── Header ────────────────────────────────────────────────────────────
    std::cout << "\n";
    {
        std::string hdr;
        auto pad = [](const std::string& s, int w) {
            if ((int)s.size() >= w) return s;
            return s + std::string(w - s.size(), ' ');
        };
        hdr = "  " + pad("IP", W_IP - 2)
            + pad("PORT",    W_PORT)
            + pad("STATE",   W_STATE)
            + pad("SERVICE", W_SERVICE)
            + "VERSION";
        std::cout << (colour ? std::string(ansi::BOLD) + hdr + ansi::RESET : hdr) << "\n";
    }
    int totalWidth = W_IP + W_PORT + W_STATE + W_SERVICE + W_VERSION;
    std::cout << "  " << std::string(static_cast<size_t>(totalWidth - 2), '-') << "\n";

    // ── Rows ───────────────────────────────────────────────────────────────
    std::string lastIP;
    for (const auto* rp : rows) {
        const ScanResult& r = *rp;

        // Build service+version combined field
        std::string svcField = r.serviceName;
        std::string verField = r.serviceVersion;

        // State string with manual padding (ANSI codes confuse setw)
        std::string stateStr = stateLabel(r.state);
        std::string statePad = stateStr
            + std::string(W_STATE > (int)stateStr.size()
                          ? W_STATE - stateStr.size() : 0, ' ');
        std::string stateOut = colour
            ? std::string(stateColor(r.state)) + ansi::BOLD + statePad + ansi::RESET
            : statePad;

        // IP column — emit blank when same IP repeats (cleaner multi-port output)
        std::string ipField = "  " + r.ip;
        std::string ipPad   = ipField
            + std::string(W_IP > (int)ipField.size() ? W_IP - ipField.size() : 0, ' ');

        // PORT field
        std::string portStr = std::to_string(r.port);
        std::string portPad = portStr
            + std::string(W_PORT > (int)portStr.size() ? W_PORT - portStr.size() : 0, ' ');

        // SERVICE field
        std::string svcPad = svcField
            + std::string(W_SERVICE > (int)svcField.size() ? W_SERVICE - svcField.size() : 0, ' ');

        std::cout << ipPad
                  << portPad
                  << stateOut
                  << svcPad
                  << verField
                  << "\n";

        lastIP = r.ip;
    }

    // ── Per-IP OS block ───────────────────────────────────────────────────
    // Collect unique IPs that have an OS guess with confidence > 0
    std::vector<std::string> seenIPs;
    for (const auto& r : results) {
        if (r.state != PortState::Open) continue;
        if (r.osGuess.confidence == 0) continue;
        if (r.osGuess.osFamily == "Unknown") continue;
        bool found = false;
        for (const auto& s : seenIPs) if (s == r.ip) { found = true; break; }
        if (!found) seenIPs.push_back(r.ip);
    }

    if (!seenIPs.empty()) {
        std::cout << "\n";
        std::cout << (colour ? std::string(ansi::BOLD) + ansi::CYAN : "")
                  << "  OS Detection Results"
                  << (colour ? std::string(ansi::RESET) : "") << "\n";
        std::cout << "  " << std::string(40, '-') << "\n";

        for (const auto& ip : seenIPs) {
            // Find the result with the highest-confidence OS guess for this IP
            const OSGuess* best = nullptr;
            for (const auto& r : results) {
                if (r.ip != ip) continue;
                if (r.osGuess.confidence == 0) continue;
                if (best == nullptr || r.osGuess.confidence > best->confidence)
                    best = &r.osGuess;
            }
            if (!best) continue;

            std::cout << "  " << (colour ? std::string(ansi::BOLD) : "")
                      << ip << (colour ? std::string(ansi::RESET) : "") << "\n";
            std::cout << "    OS Guess   : "
                      << (colour ? std::string(ansi::GREEN) : "")
                      << best->osFamily;
            if (!best->osVersion.empty()) std::cout << " " << best->osVersion;
            std::cout << (colour ? std::string(ansi::RESET) : "") << "\n";
            std::cout << "    Confidence : "
                      << (colour ? std::string(ansi::YELLOW) : "")
                      << best->confidence << "%"
                      << (colour ? std::string(ansi::RESET) : "") << "\n";
            if (!best->reasoning.empty())
                std::cout << "    Reasoning  : " << best->reasoning << "\n";
            std::cout << "\n";
        }
    } else {
        std::cout << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  printScanSummary
// ─────────────────────────────────────────────────────────────────────────────
void OutputFormatter::printScanSummary(int openCount, int totalProbes,
                                       double elapsedSeconds) const {
    const bool colour = isTTY();
    std::string elapsed;
    if (elapsedSeconds >= 1.0) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.2fs", elapsedSeconds);
        elapsed = buf;
    } else {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.0fms", elapsedSeconds * 1000.0);
        elapsed = buf;
    }

    if (colour) {
        std::cout << "  "
                  << ansi::BOLD << openCount << ansi::RESET
                  << " open port" << (openCount != 1 ? "s" : "")
                  << " found out of "
                  << ansi::BOLD << totalProbes << ansi::RESET
                  << " probe" << (totalProbes != 1 ? "s" : "")
                  << "  (" << elapsed << ")\n\n";
    } else {
        std::cout << "  " << openCount
                  << " open port" << (openCount != 1 ? "s" : "")
                  << " found out of " << totalProbes
                  << " probe" << (totalProbes != 1 ? "s" : "")
                  << "  (" << elapsed << ")\n\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Error helpers
// ─────────────────────────────────────────────────────────────────────────────
void OutputFormatter::fatalError(const std::string& msg) {
    std::cerr << "\n"
              << ansi::BOLD << ansi::RED << "  Error: " << ansi::RESET
              << msg << "\n"
              << ansi::DIM << "  Run rhscanner --help for usage information.\n"
              << ansi::RESET << "\n";
    std::exit(EXIT_FAILURE);
}

void OutputFormatter::printError(const std::string& msg) {
    std::cerr << ansi::BOLD << ansi::RED << "  Error: " << ansi::RESET << msg << "\n";
}

std::string OutputFormatter::colorize(const std::string& text,
                                      const std::string& code) {
    return code + text + ansi::RESET;
}

std::string OutputFormatter::stateLabel(PortState s) {
    switch (s) {
        case PortState::Open:     return "open";
        case PortState::Closed:   return "closed";
        case PortState::Filtered: return "filtered";
        default:                  return "unknown";
    }
}

std::string OutputFormatter::stateColor(PortState s) {
    switch (s) {
        case PortState::Open:     return ansi::GREEN;
        case PortState::Closed:   return ansi::RED;
        case PortState::Filtered: return ansi::YELLOW;
        default:                  return "";
    }
}


// ══════════════════════════════════════════════════════════════════════════════
//  ArgumentParser
// ══════════════════════════════════════════════════════════════════════════════

ScanConfig ArgumentParser::parse(int argc, char* argv[]) {
    ScanConfig cfg;

    bool isRecon = flagPresent(argc, argv, "-RH");
    if (isRecon) {
        cfg.reconMode       = true;
        cfg.doPortScan      = true;
        cfg.doServiceDetect = true;
        cfg.doOSDetect      = true;
        cfg.doBannerGrab    = true;
    }

    std::string hostExpr = extractValue(argc, argv, "-RH");
    if (hostExpr.empty()) hostExpr = extractValue(argc, argv, "-H");

    if (hostExpr.empty()) {
        OutputFormatter::fatalError(
            "-H is required.\n"
            "  Specify an IP, range, CIDR, or hostname:\n"
            "    -H 192.168.1.10\n"
            "    -H 192.168.1.0/24\n"
            "    -H scanme.nmap.org");
    }

    IPRange ipRange(hostExpr);
    if (!ipRange.isValid()) {
        OutputFormatter::fatalError(
            "Invalid host expression '" + hostExpr + "': " + ipRange.errorMsg());
    }
    cfg.targetIPs = ipRange.expand();

    if (!isRecon) {
        if (!flagPresent(argc, argv, "-P")) {
            OutputFormatter::fatalError(
                "No scan type specified.\n"
                "  Use -P to enable port scanning, or -RH for full recon.\n"
                "  Example: rhscanner -H 192.168.1.1 -P");
        }
        cfg.doPortScan = true;
    }

    std::string portExpr;
    {
        int pIdx = flagIndex(argc, argv, "-P");
        if (pIdx != -1 && pIdx + 1 < argc) {
            std::string next(argv[pIdx + 1]);
            if (!next.empty() && next[0] != '-') portExpr = next;
        }
    }

    PortRange portRange(portExpr);
    if (!portRange.isValid()) {
        OutputFormatter::fatalError(
            "Invalid port expression '" + portExpr + "': " + portRange.errorMsg());
    }
    cfg.targetPorts = portRange.expand();

    if (flagPresent(argc, argv, "-S")) {
        if (!cfg.doPortScan) {
            OutputFormatter::fatalError(
                "-S requires -P.\n  Example: rhscanner -H 192.168.1.1 -P -S");
        }
        cfg.doServiceDetect = true;
        cfg.doBannerGrab    = true;
    }

    if (flagPresent(argc, argv, "-O")) {
        if (!cfg.doPortScan) {
            OutputFormatter::fatalError(
                "-O requires -P.\n  Example: rhscanner -H 192.168.1.1 -P -O");
        }
        cfg.doOSDetect = true;
    }

    std::string tStr = extractValue(argc, argv, "-T");
    if (!tStr.empty()) {
        unsigned long tVal = 0;
        if (!parseUInt(tStr, tVal) || tVal == 0) {
            OutputFormatter::fatalError("Invalid thread count '" + tStr + "'.");
        }
        if (tVal > 500) {
            OutputFormatter::fatalError("Thread count " + tStr + " exceeds max of 500.");
        }
        cfg.numThreads = static_cast<int>(tVal);
    }

    std::string toStr = extractValue(argc, argv, "--timeout");
    if (!toStr.empty()) {
        unsigned long toVal = 0;
        if (!parseUInt(toStr, toVal) || toVal == 0) {
            OutputFormatter::fatalError("Invalid timeout '" + toStr + "' (ms).");
        }
        if (toVal > 30000) {
            OutputFormatter::fatalError("Timeout " + toStr + " ms exceeds max of 30000 ms.");
        }
        cfg.timeoutMs = static_cast<int>(toVal);
    }

    {
        int vCount = 0;
        for (int i = 1; i < argc; ++i) {
            std::string a(argv[i]);
            if (a == "-vv") { vCount = 2; break; }
            if (a == "-v")  { vCount = std::max(vCount, 1); }
        }
        cfg.verbosity = vCount;
    }

    validateConfig(cfg);
    return cfg;
}

void ArgumentParser::validateConfig(const ScanConfig& cfg) {
    if (cfg.targetIPs.empty()) {
        OutputFormatter::fatalError("Target IP list is empty after expansion.");
    }
    if (cfg.targetPorts.empty()) {
        OutputFormatter::fatalError("Port list is empty after expansion.");
    }
    if (cfg.numThreads <= 0 || cfg.numThreads > 500) {
        OutputFormatter::fatalError("Thread count must be between 1 and 500.");
    }
    if (cfg.timeoutMs <= 0 || cfg.timeoutMs > 30000) {
        OutputFormatter::fatalError("Timeout must be between 1 and 30000 ms.");
    }
}

std::string ArgumentParser::extractValue(int argc, char* argv[],
                                          const std::string& flag) {
    for (int i = 1; i < argc - 1; ++i) {
        if (flag == argv[i]) {
            std::string val(argv[i + 1]);
            if (!val.empty() && val[0] != '-') return val;
            OutputFormatter::fatalError(
                "Flag " + flag + " requires a value.  Example: " + flag + " <value>");
        }
    }
    return "";
}

bool ArgumentParser::flagPresent(int argc, char* argv[], const std::string& flag) {
    for (int i = 1; i < argc; ++i) if (flag == argv[i]) return true;
    return false;
}

int ArgumentParser::flagIndex(int argc, char* argv[], const std::string& flag) {
    for (int i = 1; i < argc; ++i) if (flag == argv[i]) return i;
    return -1;
}

}  // namespace rhs
