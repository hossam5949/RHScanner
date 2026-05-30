#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  utils/utils.h
//
//  Shared data structures and utility classes used across the entire scanner.
//  Nothing in this header may depend on scanner/, service/, os/, or threading/.
// ──────────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace rhs {

// ══════════════════════════════════════════════════════════════════════════════
//  PortState
// ══════════════════════════════════════════════════════════════════════════════

enum class PortState {
    Open,
    Closed,
    Filtered,
    Unknown
};

// ══════════════════════════════════════════════════════════════════════════════
//  OSGuess  —  result of OS fingerprinting
// ══════════════════════════════════════════════════════════════════════════════

struct OSGuess {
    std::string osFamily;    // "Linux", "Windows", "Cisco IOS", "Unknown"
    std::string osVersion;   // "3.x", "10", "" if unknown
    int         confidence;  // 0–100

    OSGuess() : osFamily("Unknown"), osVersion(""), confidence(0) {}
    OSGuess(std::string family, std::string version, int conf)
        : osFamily(std::move(family))
        , osVersion(std::move(version))
        , confidence(conf)
    {}
};

// ══════════════════════════════════════════════════════════════════════════════
//  ScanResult  —  all data collected about a single (ip, port) pair
// ══════════════════════════════════════════════════════════════════════════════

struct ScanResult {
    std::string ip;
    uint16_t    port           = 0;
    PortState   state          = PortState::Unknown;
    std::string serviceName;    // "http", "ssh", "" if unknown
    std::string serviceVersion; // from banner, may be empty
    OSGuess     osGuess;
    int         ttl            = -1;  // raw TTL from ICMP probe, -1 = not probed
    bool        bannerGrabbed  = false;

    ScanResult() = default;
    ScanResult(std::string ip_, uint16_t port_)
        : ip(std::move(ip_)), port(port_) {}
};

// ══════════════════════════════════════════════════════════════════════════════
//  ScanConfig  —  immutable configuration produced by ArgumentParser
// ══════════════════════════════════════════════════════════════════════════════

struct ScanConfig {
    std::vector<std::string>   targetIPs;
    std::vector<uint16_t>      targetPorts;

    bool doPortScan      = false;
    bool doServiceDetect = false;
    bool doOSDetect      = false;
    bool doBannerGrab    = false;
    bool reconMode       = false;  // -RH: implies all of the above

    int  numThreads      = 50;
    int  timeoutMs       = 1000;
    int  verbosity       = 0;      // 0=quiet 1=verbose 2=debug
};

// ══════════════════════════════════════════════════════════════════════════════
//  IPRange  —  parses and expands an IP expression into individual IPs
//
//  Supported formats:
//    "192.168.1.10"          single host
//    "192.168.1.1-20"        last-octet range
//    "192.168.1.0/24"        CIDR notation
// ══════════════════════════════════════════════════════════════════════════════

class IPRange {
public:
    explicit IPRange(const std::string& expr);

    // Returns the list of individual IP strings this expression expands to.
    std::vector<std::string> expand()    const;
    bool                     isValid()   const;

    // Human-readable description of the parse error, or "" if valid.
    const std::string&       errorMsg()  const;

private:
    std::string              expr_;
    std::vector<std::string> expanded_;
    bool                     valid_    = false;
    std::string              errorMsg_;

    void parseSingle(const std::string& ip);
    void parseLastOctetRange(const std::string& base, int lo, int hi);
    void parseCIDR(const std::string& ip, int prefix);

    static bool isValidIPv4(const std::string& ip);
};

// ══════════════════════════════════════════════════════════════════════════════
//  PortRange  —  parses and expands a port expression
//
//  Supported formats:
//    "80"          single port
//    "1-1024"      range
//    "22,80,443"   comma-separated list
//    ""            defaults to 1–1024
// ══════════════════════════════════════════════════════════════════════════════

class PortRange {
public:
    explicit PortRange(const std::string& expr);

    std::vector<uint16_t>  expand()   const;
    bool                   isValid()  const;

    // Human-readable description of the parse error, or "" if valid.
    const std::string&     errorMsg() const;

private:
    std::string            expr_;
    std::vector<uint16_t>  expanded_;
    bool                   valid_    = false;
    std::string            errorMsg_;

    void parseSingle(uint16_t port);
    void parseRange(uint16_t lo, uint16_t hi);
    void parseCSV(const std::string& csv, bool seen[]);
};

// ══════════════════════════════════════════════════════════════════════════════
//  ResultStore  —  thread-safe accumulator for ScanResult objects
// ══════════════════════════════════════════════════════════════════════════════

class ResultStore {
public:
    ResultStore() = default;

    // Add or update the result for (ip, port). Thread-safe.
    void addResult(const ScanResult& result);

    // Retrieve a copy of all results sorted by IP then port.
    std::vector<ScanResult> getResults() const;

    // Update only the service fields for an existing result. Thread-safe.
    void updateService(const std::string& ip, uint16_t port,
                       const std::string& name, const std::string& version);

    // Update only the OS guess for an existing result. Thread-safe.
    void updateOS(const std::string& ip, uint16_t port, const OSGuess& guess);

    // Total number of results stored.
    std::size_t count() const;

private:
    using Key = std::pair<std::string, uint16_t>;
    mutable std::mutex                  mutex_;
    std::map<Key, ScanResult>           results_;
};

// ══════════════════════════════════════════════════════════════════════════════
//  Logger  —  level-filtered, thread-safe log output to stderr
// ══════════════════════════════════════════════════════════════════════════════

class Logger {
public:
    enum class Level { Quiet = 0, Info = 1, Debug = 2 };

    explicit Logger(int verbosityLevel);

    void debug(const std::string& msg) const;
    void info(const std::string& msg)  const;
    void warn(const std::string& msg)  const;
    void error(const std::string& msg) const;

private:
    Level               level_;
    mutable std::mutex  mutex_;

    void log(const std::string& prefix, const std::string& msg) const;
};

// ══════════════════════════════════════════════════════════════════════════════
//  OutputFormatter  —  all stdout rendering; nothing else may print to stdout
// ══════════════════════════════════════════════════════════════════════════════

class OutputFormatter {
public:
    explicit OutputFormatter(int verbosity = 0);

    // Print the "RH Scanner" banner with ANSI colours (R=pink, H=blue).
    void printBanner() const;

    // Print the help/usage screen.
    static void printHelp();

    // Print a formatted table of results.
    void printResults(const std::vector<ScanResult>& results) const;

    // Print a one-line scan summary (open count, total, elapsed time).
    void printScanSummary(int openCount, int totalProbes,
                          double elapsedSeconds) const;

    // Print an overwriting progress line to stderr.
    void printProgress(int done, int total) const;

    // Print a formatted error message to stderr and exit.
    static void fatalError(const std::string& msg);

    // Print a formatted error message to stderr (no exit).
    static void printError(const std::string& msg);

private:
    int verbosity_;

    static std::string colorize(const std::string& text,
                                const std::string& ansiCode);
    static std::string stateLabel(PortState s);
    static std::string stateColor(PortState s);
};

// ══════════════════════════════════════════════════════════════════════════════
//  ArgumentParser  —  validates argv and produces a ScanConfig
// ══════════════════════════════════════════════════════════════════════════════

class ArgumentParser {
public:
    // Parse argc/argv and return a fully populated ScanConfig.
    // Calls OutputFormatter::fatalError() on any validation failure.
    ScanConfig parse(int argc, char* argv[]);

private:
    // Semantic validation after all flags are collected.
    static void validateConfig(const ScanConfig& cfg);

    // Find the value token that follows a flag, or return "".
    static std::string extractValue(int argc, char* argv[],
                                    const std::string& flag);

    // Return true if the flag appears anywhere in argv.
    static bool flagPresent(int argc, char* argv[], const std::string& flag);

    // Return the index of flag in argv, or -1.
    static int flagIndex(int argc, char* argv[], const std::string& flag);
};

}  // namespace rhs
