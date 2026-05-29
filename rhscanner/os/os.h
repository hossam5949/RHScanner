#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  os/os.h
//
//  IFingerprintStrategy — abstract strategy interface (Open/Closed principle).
//  TTLFingerprintStrategy — concrete strategy using ICMP TTL values.
//  OSDetector — runs all registered strategies and merges their guesses.
//
//  Adding a new technique (TCP window, SYN flags, banner analysis) requires
//  only a new IFingerprintStrategy subclass + one registerStrategy() call —
//  no changes to OSDetector or any caller.
// ──────────────────────────────────────────────────────────────────────────────

#include "utils/utils.h"

#include <memory>
#include <string>
#include <vector>

namespace rhs {

// ══════════════════════════════════════════════════════════════════════════════
//  IFingerprintStrategy  —  extension point for OS detection techniques
// ══════════════════════════════════════════════════════════════════════════════

class IFingerprintStrategy {
public:
    virtual ~IFingerprintStrategy() = default;

    // Probe ip and return a guess. May perform network I/O.
    // Must be safe to call concurrently from multiple threads.
    virtual OSGuess analyze(const std::string& ip) const = 0;

    // Human-readable name of this strategy (used in debug logs).
    virtual std::string name() const = 0;
};

// ══════════════════════════════════════════════════════════════════════════════
//  TTLFingerprintStrategy  —  ICMP echo → TTL → OS family
//
//  TTL thresholds (industry standard defaults):
//    255 → Cisco IOS / Solaris
//    128 → Windows
//     64 → Linux / macOS / BSD
//     60 → older HP-UX
//
//  Confidence is moderate (60) because routers decrement TTL in transit.
// ══════════════════════════════════════════════════════════════════════════════

class TTLFingerprintStrategy : public IFingerprintStrategy {
public:
    // timeoutMs — ICMP probe socket timeout
    explicit TTLFingerprintStrategy(int timeoutMs, Logger& logger);

    OSGuess     analyze(const std::string& ip) const override;
    std::string name()  const override;

private:
    // Map a raw TTL value to an OS family + version hint.
    static OSGuess ttlToGuess(int ttl);

    int     timeoutMs_;
    Logger& logger_;
};

// ══════════════════════════════════════════════════════════════════════════════
//  OSDetector  —  aggregates strategies and returns the best guess
//
//  Usage:
//    OSDetector detector;
//    detector.registerStrategy(make_unique<TTLFingerprintStrategy>(...));
//    OSGuess g = detector.detect("192.168.1.1");
// ══════════════════════════════════════════════════════════════════════════════

class OSDetector {
public:
    OSDetector() = default;

    // Take ownership of a strategy. Call before detect().
    void registerStrategy(std::unique_ptr<IFingerprintStrategy> strategy);

    // Run all registered strategies and return the highest-confidence result.
    // Returns OSGuess with confidence=0 / family="Unknown" if no strategies
    // are registered or all fail.
    OSGuess detect(const std::string& ip) const;

    // Format a guess as a human-readable string, e.g. "Linux (confidence 60%)".
    static std::string guessToString(const OSGuess& guess);

private:
    // Pick the guess with the highest confidence value.
    static OSGuess merge(const std::vector<OSGuess>& guesses);

    std::vector<std::unique_ptr<IFingerprintStrategy>> strategies_;
};

}  // namespace rhs
