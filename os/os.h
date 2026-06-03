#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  os/os.h
//
//  IFingerprintStrategy — abstract strategy interface (Open/Closed principle).
//  BannerOSStrategy     — passive banner-based OS inference (no raw sockets).
//  TTLFingerprintStrategy — TTL-based OS inference (requires icmpPing, stub).
//  OSDetector           — runs all registered strategies and merges guesses.
//
//  M7 uses passive techniques only:
//    - Banner analysis: SSH/HTTP/FTP/SMTP banners already collected by M6
//      are inspected for OS-identifying strings.  Zero additional network I/O.
//    - TTL fingerprinting: structured for future use when ICMP is available.
//      The strategy is registered but analyze() returns confidence=0 in M7
//      because icmpPing() is still a stub (requires CAP_NET_RAW).
// ──────────────────────────────────────────────────────────────────────────────

#include "utils/utils.h"

#include <memory>
#include <string>
#include <vector>

namespace rhs {

// ══════════════════════════════════════════════════════════════════════════════
//  IFingerprintStrategy  —  one OS-detection technique
// ══════════════════════════════════════════════════════════════════════════════

class IFingerprintStrategy {
public:
    virtual ~IFingerprintStrategy() = default;

    // Analyse results already in the store for the given IP.
    // Must be safe to call from a single thread (postProcess is serial).
    virtual OSGuess analyzeResults(const std::string& ip,
                                   const std::vector<ScanResult>& results) const = 0;

    virtual std::string name() const = 0;
};

// ══════════════════════════════════════════════════════════════════════════════
//  BannerOSStrategy  —  infer OS from service banners (passive, no I/O)
//
//  Evidence gathered per IP:
//    SSH banner  → "Ubuntu", "Debian", "FreeBSD", etc.
//    HTTP Server → "IIS" → Windows, "nginx"/"Apache" → Linux
//    FTP banner  → "Microsoft FTP" → Windows, "vsftpd"/"ProFTPD" → Linux
//    SMTP banner → "Exchange" → Windows, "Postfix"/"Exim" → Linux
//
//  Each indicator contributes a confidence vote.  The votes are combined
//  and normalised to [0,100].  Conflicting signals lower confidence.
// ══════════════════════════════════════════════════════════════════════════════

class BannerOSStrategy : public IFingerprintStrategy {
public:
    BannerOSStrategy() = default;

    OSGuess     analyzeResults(const std::string& ip,
                               const std::vector<ScanResult>& results) const override;
    std::string name() const override { return "banner-passive"; }

private:
    struct Vote {
        std::string family;
        int         weight;     // positive strength of evidence
        std::string reason;
    };

    // Extract OS evidence from a single ScanResult's banner + service.
    std::vector<Vote> votesFromResult(const ScanResult& r) const;

    // Collapse votes into one OSGuess.
    static OSGuess mergeVotes(const std::vector<Vote>& votes);
};

// ══════════════════════════════════════════════════════════════════════════════
//  TTLFingerprintStrategy  —  ICMP TTL → OS family
//
//  Registered but returns confidence=0 in M7 because icmpPing() is a stub
//  (requires CAP_NET_RAW / root).  Structured for easy completion in a future
//  milestone when raw socket support is added.
// ══════════════════════════════════════════════════════════════════════════════

class TTLFingerprintStrategy : public IFingerprintStrategy {
public:
    explicit TTLFingerprintStrategy(int timeoutMs, Logger& logger);

    OSGuess     analyzeResults(const std::string& ip,
                               const std::vector<ScanResult>& results) const override;
    std::string name() const override { return "ttl-fingerprint"; }

private:
    static OSGuess ttlToGuess(int ttl);

    int     timeoutMs_;
    Logger& logger_;
};

// ══════════════════════════════════════════════════════════════════════════════
//  OSDetector  —  aggregates strategies, returns the best merged guess
// ══════════════════════════════════════════════════════════════════════════════

class OSDetector {
public:
    OSDetector() = default;

    void registerStrategy(std::unique_ptr<IFingerprintStrategy> strategy);

    // Run all strategies against the collected results for ip.
    // Returns OSGuess{confidence=0} if no strategy produces a result.
    OSGuess detect(const std::string& ip,
                   const std::vector<ScanResult>& results) const;

    // Format a guess for display, e.g. "Linux  (confidence: 75%)".
    static std::string guessToString(const OSGuess& guess);

private:
    static OSGuess merge(const std::vector<OSGuess>& guesses);

    std::vector<std::unique_ptr<IFingerprintStrategy>> strategies_;
};

}  // namespace rhs
