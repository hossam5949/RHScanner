// ──────────────────────────────────────────────────────────────────────────────
//  os/os.cpp
//
//  M1 skeleton — structural stubs only.
//  TTLFingerprintStrategy::analyze(): M6
//  TTLFingerprintStrategy::ttlToGuess(): M6
//  OSDetector::detect():              M6
// ──────────────────────────────────────────────────────────────────────────────

#include "os/os.h"

#include <algorithm>

namespace rhs {

// ═════════════════════════════════════════════════════════════════════════════
//  TTLFingerprintStrategy
// ═════════════════════════════════════════════════════════════════════════════

TTLFingerprintStrategy::TTLFingerprintStrategy(int timeoutMs, Logger& logger)
    : timeoutMs_(timeoutMs)
    , logger_(logger)
{}

OSGuess TTLFingerprintStrategy::analyze(const std::string& ip) const {
    // TODO (M6):
    //   int ttl = ProbeEngine(timeoutMs_, logger_).icmpPing(ip);
    //   if (ttl < 0) return OSGuess{};
    //   return ttlToGuess(ttl);
    (void)ip;
    return OSGuess{};
}

std::string TTLFingerprintStrategy::name() const {
    return "TTL-fingerprint";
}

OSGuess TTLFingerprintStrategy::ttlToGuess(int ttl) {
    // TODO (M6): map TTL ranges to OS families.
    //
    // Planned thresholds:
    //   ttl == 255        → "Cisco IOS / Solaris",  confidence 65
    //   ttl >= 120        → "Windows",               confidence 60
    //   ttl >= 56         → "Linux / macOS",         confidence 60
    //   ttl >= 48         → "HP-UX (legacy)",        confidence 40
    //   otherwise         → "Unknown",               confidence  0
    //
    // Note: routers decrement TTL in transit, so received TTL is always
    // ≤ initial TTL. We use threshold ranges, not exact values.
    (void)ttl;
    return OSGuess{};
}

// ═════════════════════════════════════════════════════════════════════════════
//  OSDetector
// ═════════════════════════════════════════════════════════════════════════════

void OSDetector::registerStrategy(
    std::unique_ptr<IFingerprintStrategy> strategy)
{
    strategies_.push_back(std::move(strategy));
}

OSGuess OSDetector::detect(const std::string& ip) const {
    // TODO (M6): run all strategies, collect guesses, call merge()
    (void)ip;
    return OSGuess{};
}

std::string OSDetector::guessToString(const OSGuess& guess) {
    if (guess.confidence == 0 || guess.osFamily == "Unknown") {
        return "Unknown";
    }
    std::string s = guess.osFamily;
    if (!guess.osVersion.empty()) {
        s += " " + guess.osVersion;
    }
    s += " (confidence " + std::to_string(guess.confidence) + "%)";
    return s;
}

OSGuess OSDetector::merge(const std::vector<OSGuess>& guesses) {
    if (guesses.empty()) return OSGuess{};

    // TODO (M6): more sophisticated merging (voting, weighted average).
    // For now: return the single highest-confidence result.
    return *std::max_element(guesses.begin(), guesses.end(),
        [](const OSGuess& a, const OSGuess& b) {
            return a.confidence < b.confidence;
        });
}

}  // namespace rhs
