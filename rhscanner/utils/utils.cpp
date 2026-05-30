// ──────────────────────────────────────────────────────────────────────────────
//  utils/utils.cpp
//
//  Milestone implementation schedule:
//    M1: Banner, Logger, OutputFormatter stubs
//    M2: IPRange, PortRange, ArgumentParser          ← this milestone
//    M3: ResultStore
//    M7: OutputFormatter table / progress
// ──────────────────────────────────────────────────────────────────────────────

#include "utils/utils.h"

#include <algorithm>
#include <arpa/inet.h>   // inet_aton, inet_ntoa
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <netinet/in.h>  // in_addr
#include <sstream>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace rhs {

// ─────────────────────────────────────────────────────────────────────────────
//  ANSI colour constants  (translation-unit private)
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
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal string helpers  (TU-private, not in the header)
// ─────────────────────────────────────────────────────────────────────────────
namespace {

// Split s on delim and return parts (never returns empty vector).
std::vector<std::string> splitString(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim)) {
        parts.push_back(token);
    }
    if (parts.empty()) parts.push_back("");
    return parts;
}

// Trim leading/trailing ASCII whitespace.
std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    auto start = s.find_first_not_of(ws);
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(ws);
    return s.substr(start, end - start + 1);
}

// Parse a non-negative integer from s; return false if s is not a pure integer.
bool parseUInt(const std::string& s, unsigned long& out) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    try {
        out = std::stoul(s);
        return true;
    } catch (...) {
        return false;
    }
}

}  // anonymous namespace


// ══════════════════════════════════════════════════════════════════════════════
//  IPRange
// ══════════════════════════════════════════════════════════════════════════════

IPRange::IPRange(const std::string& expr) : expr_(trim(expr)) {
    if (expr_.empty()) {
        errorMsg_ = "IP expression is empty";
        return;
    }

    // Dispatch: CIDR if '/' present, range if '-' appears after first octet
    // separator, otherwise treat as single host.
    //
    // Detection order matters — try CIDR first, then range, then single.
    // A plain IP like "10.0.0.1" contains no '/' and no '-' so falls to single.

    if (expr_.find('/') != std::string::npos) {
        // ── CIDR: "192.168.1.0/24" ────────────────────────────────────────
        auto slashPos = expr_.find('/');
        std::string ipPart     = expr_.substr(0, slashPos);
        std::string prefixPart = expr_.substr(slashPos + 1);

        if (!isValidIPv4(ipPart)) {
            errorMsg_ = "Invalid IP in CIDR expression: '" + ipPart + "'";
            return;
        }

        unsigned long prefix = 0;
        if (!parseUInt(prefixPart, prefix) || prefix > 32) {
            errorMsg_ = "Invalid CIDR prefix length: '" + prefixPart
                      + "' (must be 0–32)";
            return;
        }

        parseCIDR(ipPart, static_cast<int>(prefix));

    } else if (expr_.find('-') != std::string::npos) {
        // ── Last-octet range: "192.168.1.1-20" ───────────────────────────
        // Format: a.b.c.lo-hi   where lo and hi are last-octet values.
        // We find the last '.' to split base from range.
        auto lastDot = expr_.rfind('.');
        if (lastDot == std::string::npos) {
            errorMsg_ = "Invalid IP range format: '" + expr_
                      + "' (expected a.b.c.lo-hi)";
            return;
        }

        std::string base      = expr_.substr(0, lastDot);          // "192.168.1"
        std::string rangePart = expr_.substr(lastDot + 1);         // "1-20"

        auto dashPos = rangePart.find('-');
        if (dashPos == std::string::npos) {
            // No '-' in last octet — might just be a single IP containing dots
            parseSingle(expr_);
            return;
        }

        std::string loPart = rangePart.substr(0, dashPos);
        std::string hiPart = rangePart.substr(dashPos + 1);

        unsigned long lo = 0, hi = 0;
        if (!parseUInt(loPart, lo) || lo > 255) {
            errorMsg_ = "Invalid range start '" + loPart
                      + "' in expression '" + expr_ + "'";
            return;
        }
        if (!parseUInt(hiPart, hi) || hi > 255) {
            errorMsg_ = "Invalid range end '" + hiPart
                      + "' in expression '" + expr_ + "'";
            return;
        }
        if (lo > hi) {
            errorMsg_ = "Range start (" + loPart + ") is greater than end ("
                      + hiPart + ")";
            return;
        }

        // Validate the base (first three octets)
        if (!isValidIPv4(base + ".0")) {
            errorMsg_ = "Invalid base address '" + base
                      + "' in expression '" + expr_ + "'";
            return;
        }

        parseLastOctetRange(base, static_cast<int>(lo),
                                  static_cast<int>(hi));

    } else {
        // ── Single host ────────────────────────────────────────────────────
        parseSingle(expr_);
    }
}

std::vector<std::string> IPRange::expand() const { return expanded_; }
bool                     IPRange::isValid()  const { return valid_; }
const std::string&       IPRange::errorMsg() const { return errorMsg_; }

// ── private helpers ───────────────────────────────────────────────────────────

void IPRange::parseSingle(const std::string& ip) {
    if (!isValidIPv4(ip)) {
        errorMsg_ = "Invalid IPv4 address: '" + ip + "'";
        return;
    }
    expanded_.push_back(ip);
    valid_ = true;
}

void IPRange::parseLastOctetRange(const std::string& base, int lo, int hi) {
    expanded_.reserve(static_cast<size_t>(hi - lo + 1));
    for (int octet = lo; octet <= hi; ++octet) {
        expanded_.push_back(base + "." + std::to_string(octet));
    }
    valid_ = true;
}

void IPRange::parseCIDR(const std::string& ip, int prefix) {
    // Convert dotted-decimal to 32-bit host-order integer.
    struct in_addr addr{};
    inet_aton(ip.c_str(), &addr);
    uint32_t network = ntohl(addr.s_addr);

    // Build the host mask: /24 → 0x000000FF
    uint32_t hostBits = static_cast<uint32_t>(32 - prefix);
    uint32_t hostMask = (hostBits == 32)
                      ? 0xFFFFFFFFu
                      : ((1u << hostBits) - 1u);

    // Network base (all host bits zeroed).
    uint32_t base = network & ~hostMask;

    // /32 → single host; /31 → two addresses (point-to-point RFC 3021);
    // otherwise skip network (.0) and broadcast (.255) for /24 and narrower.
    uint32_t first, last;
    if (prefix >= 31) {
        // /31 and /32: include all addresses
        first = base;
        last  = base | hostMask;
    } else {
        // Skip network address and broadcast address
        first = base + 1;
        last  = (base | hostMask) - 1;
    }

    if (first > last) {
        // /32 case with prefix==32 ends up here when adjusted incorrectly;
        // handle gracefully by restoring
        first = base;
        last  = base;
    }

    expanded_.reserve(static_cast<size_t>(last - first + 1));
    for (uint32_t host = first; host <= last; ++host) {
        // Convert back to dotted-decimal.
        struct in_addr a{};
        a.s_addr = htonl(host);
        expanded_.push_back(std::string(inet_ntoa(a)));
    }
    valid_ = true;
}

bool IPRange::isValidIPv4(const std::string& ip) {
    // Split on '.'; must have exactly 4 octets, each 0–255.
    auto parts = splitString(ip, '.');
    if (parts.size() != 4) return false;
    for (const auto& part : parts) {
        if (part.empty() || part.size() > 3) return false;
        unsigned long val = 0;
        if (!parseUInt(part, val) || val > 255) return false;
        // Reject leading zeros (e.g. "01") — ambiguous and non-standard.
        if (part.size() > 1 && part[0] == '0') return false;
    }
    return true;
}


// ══════════════════════════════════════════════════════════════════════════════
//  PortRange
// ══════════════════════════════════════════════════════════════════════════════

PortRange::PortRange(const std::string& expr) : expr_(trim(expr)) {
    // Heap-allocate the dedup bitset to avoid stack overflow on large ranges.
    // 65536 bytes = 64 KB, fine on heap, potentially fatal on stack inside
    // deeply nested call chains.
    auto seen = std::make_unique<bool[]>(65536);
    std::fill(seen.get(), seen.get() + 65536, false);

    auto addPort = [&](uint16_t p) {
        if (!seen[p]) { seen[p] = true; expanded_.push_back(p); }
    };

    auto addRange = [&](uint16_t lo, uint16_t hi) {
        expanded_.reserve(expanded_.size() + static_cast<size_t>(hi - lo + 1));
        // Use int for the loop variable to avoid uint16_t wrapping past 65535.
        for (int p = static_cast<int>(lo); p <= static_cast<int>(hi); ++p) {
            auto u = static_cast<uint16_t>(p);
            if (!seen[u]) { seen[u] = true; expanded_.push_back(u); }
        }
        valid_ = true;
    };

    if (expr_.empty()) {
        addRange(1, 1024);
        return;
    }

    if (expr_.find(',') != std::string::npos) {
        parseCSV(expr_, seen.get());
        return;
    }

    if (expr_.find('-') != std::string::npos) {
        auto dashPos = expr_.find('-');
        std::string loPart = expr_.substr(0, dashPos);
        std::string hiPart = expr_.substr(dashPos + 1);

        unsigned long lo = 0, hi = 0;
        if (!parseUInt(loPart, lo) || lo == 0 || lo > 65535) {
            errorMsg_ = "Invalid port range start '" + loPart
                      + "' (must be 1–65535)";
            return;
        }
        if (!parseUInt(hiPart, hi) || hi == 0 || hi > 65535) {
            errorMsg_ = "Invalid port range end '" + hiPart
                      + "' (must be 1–65535)";
            return;
        }
        if (lo > hi) {
            errorMsg_ = "Port range start (" + loPart
                      + ") is greater than end (" + hiPart + ")";
            return;
        }
        addRange(static_cast<uint16_t>(lo), static_cast<uint16_t>(hi));
        return;
    }

    unsigned long val = 0;
    if (!parseUInt(expr_, val) || val == 0 || val > 65535) {
        errorMsg_ = "Invalid port '" + expr_ + "' (must be 1–65535)";
        return;
    }
    addPort(static_cast<uint16_t>(val));
    valid_ = true;
}

std::vector<uint16_t> PortRange::expand() const { return expanded_; }
bool                  PortRange::isValid()  const { return valid_; }
const std::string&    PortRange::errorMsg() const { return errorMsg_; }

// ── private helpers ───────────────────────────────────────────────────────────

void PortRange::parseSingle(uint16_t port) {
    // Called only from CSV path; constructor handles the direct single-port case.
    expanded_.push_back(port);
    valid_ = true;
}

void PortRange::parseRange(uint16_t lo, uint16_t hi) {
    // Use int for the loop variable — uint16_t wraps to 0 after 65535,
    // turning a finite range into an infinite loop.
    expanded_.reserve(expanded_.size() + static_cast<size_t>(hi - lo + 1));
    for (int p = static_cast<int>(lo); p <= static_cast<int>(hi); ++p) {
        expanded_.push_back(static_cast<uint16_t>(p));
    }
    valid_ = true;
}

void PortRange::parseCSV(const std::string& csv, bool seen[]) {
    auto tokens = splitString(csv, ',');
    for (const auto& raw : tokens) {
        std::string token = trim(raw);
        if (token.empty()) {
            errorMsg_ = "Empty token in port list '" + csv + "'";
            valid_ = false;
            expanded_.clear();
            return;
        }

        if (token.find('-') != std::string::npos) {
            // Token is itself a sub-range.
            auto dashPos = token.find('-');
            std::string loPart = token.substr(0, dashPos);
            std::string hiPart = token.substr(dashPos + 1);

            unsigned long lo = 0, hi = 0;
            if (!parseUInt(loPart, lo) || lo == 0 || lo > 65535) {
                errorMsg_ = "Invalid port '" + loPart + "' in list '" + csv + "'";
                valid_ = false; expanded_.clear(); return;
            }
            if (!parseUInt(hiPart, hi) || hi == 0 || hi > 65535) {
                errorMsg_ = "Invalid port '" + hiPart + "' in list '" + csv + "'";
                valid_ = false; expanded_.clear(); return;
            }
            if (lo > hi) {
                errorMsg_ = "Port range start (" + loPart + ") > end ("
                          + hiPart + ") in list '" + csv + "'";
                valid_ = false; expanded_.clear(); return;
            }
            expanded_.reserve(expanded_.size() + static_cast<size_t>(hi - lo + 1));
            for (int p = static_cast<int>(lo); p <= static_cast<int>(hi); ++p) {
                uint16_t u = static_cast<uint16_t>(p);
                if (!seen[u]) { seen[u] = true; expanded_.push_back(u); }
            }

        } else {
            unsigned long val = 0;
            if (!parseUInt(token, val) || val == 0 || val > 65535) {
                errorMsg_ = "Invalid port '" + token
                          + "' in list '" + csv + "' (must be 1–65535)";
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
    // Upsert: if the key already exists the new result overwrites it.
    // In M3 (serial scan) each (ip, port) pair is written exactly once,
    // but M5/M6 may call addResult again to enrich an existing entry.
    std::lock_guard<std::mutex> lock(mutex_);
    Key k{ result.ip, result.port };
    results_[k] = result;
}

std::vector<ScanResult> ResultStore::getResults() const {
    // Returns all results in sorted order (map iteration order = key order
    // = lexicographic IP string then ascending port — good enough for M3).
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ScanResult> out;
    out.reserve(results_.size());
    for (const auto& kv : results_) {
        out.push_back(kv.second);
    }
    return out;
}

void ResultStore::updateService(const std::string& ip, uint16_t port,
                                const std::string& name,
                                const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Key k{ ip, port };
    auto it = results_.find(k);
    if (it != results_.end()) {
        it->second.serviceName    = name;
        it->second.serviceVersion = version;
    }
    // If the key is not found the probe result was never stored — no-op.
    // This cannot happen in normal flow (tcpConnect always calls addResult
    // before postProcess calls updateService), but is safe to ignore.
}

void ResultStore::updateOS(const std::string& ip, uint16_t port,
                           const OSGuess& guess) {
    // TODO (M6)
    (void)ip; (void)port; (void)guess;
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

void Logger::warn(const std::string& msg) const {
    log("[WRN]", msg);
}

void Logger::error(const std::string& msg) const {
    log("[ERR]", msg);
}

void Logger::log(const std::string& prefix, const std::string& msg) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cerr << prefix << " " << msg << "\n";
}


// ══════════════════════════════════════════════════════════════════════════════
//  OutputFormatter
// ══════════════════════════════════════════════════════════════════════════════

OutputFormatter::OutputFormatter(int verbosity) : verbosity_(verbosity) {}

void OutputFormatter::printBanner() const {
    std::cout << "\n";
    std::cout << "  "
              << ansi::BOLD << ansi::PINK << "R" << ansi::RESET
              << ansi::BOLD << ansi::BLUE << "H" << ansi::RESET
              << ansi::BOLD << " Scanner"  << ansi::RESET
              << "  v0.1.0\n";
    std::cout << "  "
              << ansi::DIM
              << "A modular network scanner — educational use only"
              << ansi::RESET << "\n\n";
}

void OutputFormatter::printHelp() {
    // Coloured section headers, monospaced flag column.
    std::cout
        << "\n"
        << ansi::BOLD << "  Usage:" << ansi::RESET
        << "  rhscanner [OPTIONS]\n\n"

        << ansi::BOLD << ansi::CYAN << "  Target\n" << ansi::RESET
        << "    " << ansi::BOLD << "-H"  << ansi::RESET
        << " <host>          Single IP, CIDR, or last-octet range\n"
        << "                      "
        << ansi::DIM << "192.168.1.10  |  192.168.1.0/24  |  192.168.1.1-20\n"
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
        << "                   Service detection   (requires -P or -RH)\n"
        << "    " << ansi::BOLD << "-O" << ansi::RESET
        << "                   OS detection         (requires -P or -RH)\n\n"

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
        << "    rhscanner -RH 192.168.1.10\n\n";
}

void OutputFormatter::printResults(const std::vector<ScanResult>& results) const {
    // ── Filter: verbosity 0 shows only Open; verbosity ≥ 1 shows all ──────
    std::vector<const ScanResult*> rows;
    rows.reserve(results.size());
    for (const auto& r : results) {
        if (verbosity_ >= 1 || r.state == PortState::Open) {
            rows.push_back(&r);
        }
    }

    if (rows.empty()) {
        std::cout << "  No open ports found.\n\n";
        return;
    }

    // ── Column widths ──────────────────────────────────────────────────────
    // IP: 15 chars (longest dotted-decimal: "xxx.xxx.xxx.xxx")
    // PORT: 5 chars (max "65535")
    // STATE: 8 chars ("FILTERED")
    // SERVICE: 12 chars (populated in M5; blank in M3)
    const int W_IP      = 16;
    const int W_PORT    = 6;
    const int W_STATE   = 10;
    const int W_SERVICE = 14;

    // ── Header ────────────────────────────────────────────────────────────
    std::cout << "\n";
    std::cout << ansi::BOLD
              << std::left
              << std::setw(W_IP)      << "  IP"
              << std::setw(W_PORT)    << "PORT"
              << std::setw(W_STATE)   << "STATE"
              << std::setw(W_SERVICE) << "SERVICE"
              << ansi::RESET << "\n";

    // Separator line
    int totalWidth = W_IP + W_PORT + W_STATE + W_SERVICE;
    std::cout << "  " << std::string(static_cast<size_t>(totalWidth - 2), '-') << "\n";

    // ── Rows ───────────────────────────────────────────────────────────────
    for (const auto* rp : rows) {
        const ScanResult& r = *rp;

        // Colour the state column
        std::string stateStr  = stateLabel(r.state);
        std::string stateCol  = stateColor(r.state);

        // Pad the coloured state manually — ANSI codes add invisible chars
        // that confuse std::setw, so we pad before colourising.
        std::string statePadded = stateStr
            + std::string(static_cast<size_t>(W_STATE) > stateStr.size()
                          ? W_STATE - stateStr.size() : 0, ' ');

        std::cout << std::left
                  << std::setw(W_IP)   << ("  " + r.ip)
                  << std::setw(W_PORT) << r.port
                  << stateCol << ansi::BOLD << statePadded << ansi::RESET
                  << std::setw(W_SERVICE) << r.serviceName  // blank in M3
                  << "\n";
    }

    std::cout << "\n";
}

void OutputFormatter::printScanSummary(int openCount, int totalProbes,
                                       double elapsedSeconds) const {
    // Format elapsed time as Xs or Xms depending on magnitude.
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

    std::cout << "  "
              << ansi::BOLD << openCount << ansi::RESET
              << " open port" << (openCount != 1 ? "s" : "")
              << " found out of "
              << ansi::BOLD << totalProbes << ansi::RESET
              << " probe" << (totalProbes != 1 ? "s" : "")
              << "  (" << elapsed << ")\n\n";
}

void OutputFormatter::printProgress(int done, int total) const {
    // TODO (M4/M7)
    (void)done; (void)total;
}

void OutputFormatter::fatalError(const std::string& msg) {
    std::cerr << "\n"
              << ansi::BOLD << ansi::RED << "  Error: " << ansi::RESET
              << msg << "\n"
              << ansi::DIM
              << "  Run rhscanner --help for usage information.\n"
              << ansi::RESET << "\n";
    std::exit(EXIT_FAILURE);
}

void OutputFormatter::printError(const std::string& msg) {
    std::cerr << ansi::BOLD << ansi::RED << "  Error: " << ansi::RESET
              << msg << "\n";
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

    // ── Recon mode: -RH <host> ─────────────────────────────────────────────
    // Must be checked before -H to avoid -RH matching a -H prefix check.
    bool isRecon = flagPresent(argc, argv, "-RH");
    if (isRecon) {
        cfg.reconMode       = true;
        cfg.doPortScan      = true;
        cfg.doServiceDetect = true;
        cfg.doOSDetect      = true;
        cfg.doBannerGrab    = true;
    }

    // ── Host: -H or -RH ───────────────────────────────────────────────────
    // Both flags carry the host as the next token.
    std::string hostExpr = extractValue(argc, argv, "-RH");
    if (hostExpr.empty()) {
        hostExpr = extractValue(argc, argv, "-H");
    }

    if (hostExpr.empty()) {
        OutputFormatter::fatalError(
            "-H is required.\n"
            "  Specify a single IP, a range, or a CIDR block:\n"
            "    -H 192.168.1.10\n"
            "    -H 192.168.1.1-20\n"
            "    -H 192.168.1.0/24");
    }

    IPRange ipRange(hostExpr);
    if (!ipRange.isValid()) {
        OutputFormatter::fatalError(
            "Invalid host expression '" + hostExpr + "': "
            + ipRange.errorMsg());
    }
    cfg.targetIPs = ipRange.expand();

    // ── Port scan: -P [range] ─────────────────────────────────────────────
    if (!isRecon) {
        if (!flagPresent(argc, argv, "-P")) {
            OutputFormatter::fatalError(
                "No scan type specified.\n"
                "  Use -P to enable port scanning, or -RH for full recon.\n"
                "  Example: rhscanner -H 192.168.1.1 -P");
        }
        cfg.doPortScan = true;
    }

    // Collect the port range expression.  The token immediately after -P is
    // the range only if it does NOT start with '-' (i.e. it's not another flag).
    std::string portExpr = "";
    {
        int pIdx = flagIndex(argc, argv, "-P");
        if (pIdx != -1 && pIdx + 1 < argc) {
            std::string next(argv[pIdx + 1]);
            if (!next.empty() && next[0] != '-') {
                portExpr = next;  // e.g. "80", "1-1024", "22,80,443"
            }
        }
    }

    PortRange portRange(portExpr);   // empty portExpr → default 1-1024
    if (!portRange.isValid()) {
        OutputFormatter::fatalError(
            "Invalid port expression '" + portExpr + "': "
            + portRange.errorMsg());
    }
    cfg.targetPorts = portRange.expand();

    // ── Service detection: -S ─────────────────────────────────────────────
    if (flagPresent(argc, argv, "-S")) {
        if (!cfg.doPortScan) {
            OutputFormatter::fatalError(
                "-S (service detection) requires -P (port scan).\n"
                "  Example: rhscanner -H 192.168.1.1 -P -S");
        }
        cfg.doServiceDetect = true;
        cfg.doBannerGrab    = true;
    }

    // ── OS detection: -O ─────────────────────────────────────────────────
    if (flagPresent(argc, argv, "-O")) {
        if (!cfg.doPortScan) {
            OutputFormatter::fatalError(
                "-O (OS detection) requires -P (port scan).\n"
                "  Example: rhscanner -H 192.168.1.1 -P -O");
        }
        cfg.doOSDetect = true;
    }

    // ── Thread count: -T <n> ──────────────────────────────────────────────
    std::string tStr = extractValue(argc, argv, "-T");
    if (!tStr.empty()) {
        unsigned long tVal = 0;
        if (!parseUInt(tStr, tVal) || tVal == 0) {
            OutputFormatter::fatalError(
                "Invalid thread count '" + tStr + "'.\n"
                "  -T requires a positive integer, e.g. -T 100");
        }
        if (tVal > 500) {
            OutputFormatter::fatalError(
                "Thread count " + tStr + " exceeds maximum of 500.\n"
                "  Use -T 500 or lower.");
        }
        cfg.numThreads = static_cast<int>(tVal);
    }

    // ── Socket timeout: --timeout <ms> ────────────────────────────────────
    std::string toStr = extractValue(argc, argv, "--timeout");
    if (!toStr.empty()) {
        unsigned long toVal = 0;
        if (!parseUInt(toStr, toVal) || toVal == 0) {
            OutputFormatter::fatalError(
                "Invalid timeout '" + toStr + "'.\n"
                "  --timeout requires a positive integer in milliseconds,\n"
                "  e.g. --timeout 2000");
        }
        if (toVal > 30000) {
            OutputFormatter::fatalError(
                "Timeout " + toStr + " ms is unreasonably large (max 30000 ms).");
        }
        cfg.timeoutMs = static_cast<int>(toVal);
    }

    // ── Verbosity: -v / -vv ───────────────────────────────────────────────
    {
        // Count how many times -v appears (exact flag matching; -vv is a
        // separate flag rather than two -v tokens, so we check both).
        int vCount = 0;
        for (int i = 1; i < argc; ++i) {
            std::string a(argv[i]);
            if (a == "-vv") { vCount = 2; break; }
            if (a == "-v")  { vCount = std::max(vCount, 1); }
        }
        cfg.verbosity = vCount;
    }

    // ── Final semantic validation ─────────────────────────────────────────
    validateConfig(cfg);

    return cfg;
}

// ─────────────────────────────────────────────────────────────────────────────

void ArgumentParser::validateConfig(const ScanConfig& cfg) {
    if (cfg.targetIPs.empty()) {
        OutputFormatter::fatalError(
            "Target IP list is empty after expansion.\n"
            "  Check that the host expression is valid.");
    }
    if (cfg.targetPorts.empty()) {
        OutputFormatter::fatalError(
            "Port list is empty after expansion.\n"
            "  Check that the port expression is valid.");
    }
    if (cfg.numThreads <= 0 || cfg.numThreads > 500) {
        OutputFormatter::fatalError(
            "Thread count must be between 1 and 500.");
    }
    if (cfg.timeoutMs <= 0 || cfg.timeoutMs > 30000) {
        OutputFormatter::fatalError(
            "Timeout must be between 1 and 30000 ms.");
    }
}

// ─────────────────────────────────────────────────────────────────────────────

std::string ArgumentParser::extractValue(int argc, char* argv[],
                                          const std::string& flag) {
    for (int i = 1; i < argc - 1; ++i) {
        if (flag == argv[i]) {
            // The value must not look like another flag.
            std::string val(argv[i + 1]);
            if (!val.empty() && val[0] != '-') {
                return val;
            }
            // Flag found but next token is another flag — value is missing.
            OutputFormatter::fatalError(
                "Flag " + flag + " requires a value.\n"
                "  Example: " + flag + " <value>");
        }
    }
    // Flag not present or is the last token (no value following).
    return "";
}

bool ArgumentParser::flagPresent(int argc, char* argv[],
                                  const std::string& flag) {
    for (int i = 1; i < argc; ++i) {
        if (flag == argv[i]) return true;
    }
    return false;
}

int ArgumentParser::flagIndex(int argc, char* argv[],
                               const std::string& flag) {
    for (int i = 1; i < argc; ++i) {
        if (flag == argv[i]) return i;
    }
    return -1;
}

}  // namespace rhs
