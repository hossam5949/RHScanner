// ──────────────────────────────────────────────────────────────────────────────
//  utils/utils.cpp
//
//  M1 skeleton — stubs only.
//  Full implementations are introduced per milestone:
//    M2: ArgumentParser, IPRange, PortRange
//    M3: ResultStore
//    M7: OutputFormatter, Logger
// ──────────────────────────────────────────────────────────────────────────────

#include "utils/utils.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace rhs {

// ─────────────────────────────────────────────────────────────────────────────
//  ANSI colour constants (module-private)
// ─────────────────────────────────────────────────────────────────────────────
namespace ansi {
    static const char* RESET   = "\033[0m";
    static const char* PINK    = "\033[38;5;213m";   // used for 'R'
    static const char* BLUE    = "\033[38;5;75m";    // used for 'H'
    static const char* RED     = "\033[31m";
    static const char* GREEN   = "\033[32m";
    static const char* YELLOW  = "\033[33m";
    static const char* BOLD    = "\033[1m";
}

// ═════════════════════════════════════════════════════════════════════════════
//  IPRange
// ═════════════════════════════════════════════════════════════════════════════

IPRange::IPRange(const std::string& expr) : expr_(expr) {
    // TODO (M2): implement CIDR / range / single parsing
    (void)expr_;
}

std::vector<std::string> IPRange::expand() const {
    // TODO (M2): return expanded_
    return {};
}

bool IPRange::isValid() const {
    // TODO (M2): return valid_
    return false;
}

void IPRange::parseSingle(const std::string& ip) {
    // TODO (M2)
    (void)ip;
}

void IPRange::parseLastOctetRange(const std::string& base, int lo, int hi) {
    // TODO (M2)
    (void)base; (void)lo; (void)hi;
}

void IPRange::parseCIDR(const std::string& ip, int prefix) {
    // TODO (M2)
    (void)ip; (void)prefix;
}

bool IPRange::isValidIPv4(const std::string& ip) {
    // TODO (M2)
    (void)ip;
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
//  PortRange
// ═════════════════════════════════════════════════════════════════════════════

PortRange::PortRange(const std::string& expr) : expr_(expr) {
    // TODO (M2)
    (void)expr_;
}

std::vector<uint16_t> PortRange::expand() const {
    // TODO (M2): return expanded_
    return {};
}

bool PortRange::isValid() const {
    // TODO (M2): return valid_
    return false;
}

void PortRange::parseSingle(uint16_t port) {
    // TODO (M2)
    (void)port;
}

void PortRange::parseRange(uint16_t lo, uint16_t hi) {
    // TODO (M2)
    (void)lo; (void)hi;
}

void PortRange::parseCSV(const std::string& csv) {
    // TODO (M2)
    (void)csv;
}

// ═════════════════════════════════════════════════════════════════════════════
//  ResultStore
// ═════════════════════════════════════════════════════════════════════════════

void ResultStore::addResult(const ScanResult& result) {
    // TODO (M3)
    (void)result;
}

std::vector<ScanResult> ResultStore::getResults() const {
    // TODO (M3): return sorted copy
    return {};
}

void ResultStore::updateService(const std::string& ip, uint16_t port,
                                const std::string& name,
                                const std::string& version) {
    // TODO (M5)
    (void)ip; (void)port; (void)name; (void)version;
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

// ═════════════════════════════════════════════════════════════════════════════
//  Logger
// ═════════════════════════════════════════════════════════════════════════════

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

// ═════════════════════════════════════════════════════════════════════════════
//  OutputFormatter
// ═════════════════════════════════════════════════════════════════════════════

OutputFormatter::OutputFormatter(int verbosity) : verbosity_(verbosity) {}

void OutputFormatter::printBanner() const {
    // ┌─────────────────────────────────────────────────┐
    // │   RH Scanner banner                              │
    // │   'R' rendered in pink, 'H' rendered in blue     │
    // │   Remaining characters use bold white            │
    // └─────────────────────────────────────────────────┘

    std::cout << "\n";
    std::cout << "  "
              << ansi::BOLD << ansi::PINK  << "R" << ansi::RESET
              << ansi::BOLD << ansi::BLUE  << "H" << ansi::RESET
              << ansi::BOLD              << " Scanner"
              << ansi::RESET
              << "  v0.1.0\n";
    std::cout << "  "
              << "A modular network scanner — educational use only\n";
    std::cout << "\n";
}

void OutputFormatter::printHelp() {
    std::cout <<
        "\n"
        "  Usage: rhscanner [OPTIONS]\n"
        "\n"
        "  Target:\n"
        "    -H <host>        Single IP, CIDR, or range\n"
        "                     e.g. 192.168.1.1  /  192.168.1.0/24  /  192.168.1.1-20\n"
        "    -RH <host>       Full recon mode (implies -P -S -O)\n"
        "\n"
        "  Scan types:\n"
        "    -P [range]       Port scan (default range: 1-1024)\n"
        "                     e.g. -P  |  -P 80  |  -P 1-65535  |  -P 22,80,443\n"
        "    -S               Service detection  (requires -P or -RH)\n"
        "    -O               OS detection        (requires -P or -RH)\n"
        "\n"
        "  Performance:\n"
        "    -T <n>           Thread count  (default: 50, max: 500)\n"
        "    --timeout <ms>   Per-probe socket timeout  (default: 1000ms)\n"
        "\n"
        "  Output:\n"
        "    -v               Verbose: show closed/filtered ports\n"
        "    -vv              Debug:   log socket operations\n"
        "\n"
        "  Misc:\n"
        "    -h, --help       This help screen\n"
        "    --version        Print version string\n"
        "\n"
        "  Examples:\n"
        "    rhscanner -H 192.168.1.10 -P\n"
        "    rhscanner -H 192.168.1.10 -P 1-1024 -S\n"
        "    rhscanner -H 192.168.1.10 -P 80,443 -S -O\n"
        "    rhscanner -H 192.168.1.1-50 -P 22 -T 100\n"
        "    rhscanner -RH 192.168.1.10\n"
        "\n";
}

void OutputFormatter::printResults(const std::vector<ScanResult>& results) const {
    // TODO (M3/M7): render formatted table
    (void)results;
    std::cout << "[OutputFormatter::printResults — not yet implemented]\n";
}

void OutputFormatter::printScanSummary(int openCount, int totalProbes,
                                       double elapsedSeconds) const {
    // TODO (M7)
    (void)openCount; (void)totalProbes; (void)elapsedSeconds;
}

void OutputFormatter::printProgress(int done, int total) const {
    // TODO (M4/M7)
    (void)done; (void)total;
}

void OutputFormatter::fatalError(const std::string& msg) {
    std::cerr << ansi::RED << "Error: " << ansi::RESET << msg << "\n"
              << "       Run with --help for usage information.\n";
    std::exit(EXIT_FAILURE);
}

void OutputFormatter::printError(const std::string& msg) {
    std::cerr << ansi::RED << "Error: " << ansi::RESET << msg << "\n";
}

// private helpers

std::string OutputFormatter::colorize(const std::string& text,
                                      const std::string& ansiCode) {
    return ansiCode + text + ansi::RESET;
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

// ═════════════════════════════════════════════════════════════════════════════
//  ArgumentParser
// ═════════════════════════════════════════════════════════════════════════════

ScanConfig ArgumentParser::parse(int argc, char* argv[]) {
    // TODO (M2): full implementation
    (void)argc; (void)argv;
    return ScanConfig{};
}

void ArgumentParser::validateConfig(const ScanConfig& cfg) {
    // TODO (M2)
    (void)cfg;
}

std::string ArgumentParser::extractValue(int argc, char* argv[],
                                         const std::string& flag) {
    // TODO (M2)
    (void)argc; (void)argv; (void)flag;
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
