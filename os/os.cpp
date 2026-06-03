// ──────────────────────────────────────────────────────────────────────────────
//  os/os.cpp  —  M7 OS detection: passive banner analysis + TTL stub
// ──────────────────────────────────────────────────────────────────────────────

#include "os/os.h"

#include <algorithm>
#include <cstring>

namespace rhs {

// ══════════════════════════════════════════════════════════════════════════════
//  BannerOSStrategy
//
//  Passive technique: inspects raw banners and service version strings already
//  collected by M6 banner grabbing.  Zero additional network I/O.
//
//  Voting model:
//    - Each open port's banner is analysed for OS-identifying strings.
//    - Each match produces a Vote{family, weight, reason}.
//    - mergeVotes() sums weights per family, picks the winner, and computes
//      confidence as min(winner_weight * scale, 100).
//    - Conflicting evidence (Windows + Linux votes) reduces confidence.
// ══════════════════════════════════════════════════════════════════════════════

static std::string toLower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

static bool contains(const std::string& haystack, const std::string& needle) {
    return toLower(haystack).find(toLower(needle)) != std::string::npos;
}

std::vector<BannerOSStrategy::Vote>
BannerOSStrategy::votesFromResult(const ScanResult& r) const {
    std::vector<Vote> votes;
    const std::string& banner  = r.rawBanner;
    const std::string& version = r.serviceVersion;
    const std::string& svc     = r.serviceName;

    // ── SSH banners ───────────────────────────────────────────────────────
    // SSH-2.0-OpenSSH_9.3p2 Ubuntu-1ubuntu3.6
    // SSH-2.0-OpenSSH_8.9p1 Debian-3ubuntu0.6
    // SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u1
    if (svc == "ssh") {
        if (contains(banner, "ubuntu"))         votes.push_back({"Linux", 40, "SSH banner: Ubuntu"});
        if (contains(banner, "debian"))         votes.push_back({"Linux", 40, "SSH banner: Debian"});
        if (contains(banner, "raspbian"))       votes.push_back({"Linux", 40, "SSH banner: Raspbian"});
        if (contains(banner, "fedora"))         votes.push_back({"Linux", 40, "SSH banner: Fedora"});
        if (contains(banner, "centos"))         votes.push_back({"Linux", 40, "SSH banner: CentOS"});
        if (contains(banner, "rhel") ||
            contains(banner, "redhat"))         votes.push_back({"Linux", 40, "SSH banner: RHEL"});
        if (contains(banner, "alpine"))         votes.push_back({"Linux", 35, "SSH banner: Alpine"});
        if (contains(banner, "freebsd"))        votes.push_back({"FreeBSD", 45, "SSH banner: FreeBSD"});
        if (contains(banner, "openbsd"))        votes.push_back({"OpenBSD", 45, "SSH banner: OpenBSD"});
        if (contains(banner, "netbsd"))         votes.push_back({"NetBSD",  45, "SSH banner: NetBSD"});
        if (contains(banner, "openssh") &&
            votes.empty())                      votes.push_back({"Linux", 20, "SSH: OpenSSH (likely Linux)"});
        if (contains(version, "openssh"))       votes.push_back({"Linux", 15, "SSH version: OpenSSH"});
        if (contains(banner, "putty"))          votes.push_back({"Windows", 30, "SSH: PuTTY server"});
        if (contains(banner, "bitvise"))        votes.push_back({"Windows", 35, "SSH: Bitvise"});
        if (contains(banner, "winsshd") ||
            contains(banner, "copyssh"))        votes.push_back({"Windows", 35, "SSH: Windows SSH"});
    }

    // ── HTTP / HTTP-alt banners ───────────────────────────────────────────
    if (svc == "http" || svc == "http-alt" || svc == "http-alt2"
        || svc == "grafana" || svc == "jupyter" || svc == "webmin") {
        // Server header in version field
        if (contains(version, "iis") ||
            contains(version, "microsoft"))     votes.push_back({"Windows", 45, "HTTP Server: IIS/Microsoft"});
        if (contains(version, "apache"))        votes.push_back({"Linux",   30, "HTTP Server: Apache"});
        if (contains(version, "nginx"))         votes.push_back({"Linux",   30, "HTTP Server: nginx"});
        if (contains(version, "lighttpd"))      votes.push_back({"Linux",   30, "HTTP Server: lighttpd"});
        if (contains(version, "cherokee"))      votes.push_back({"Linux",   25, "HTTP Server: Cherokee"});
        if (contains(banner, "x-powered-by: asp.net") ||
            contains(banner, "x-aspnet"))       votes.push_back({"Windows", 40, "HTTP: ASP.NET header"});
        if (contains(banner, "x-powered-by: php")) votes.push_back({"Linux", 20, "HTTP: PHP (likely Linux)"});
        // Specific distro clues in response headers
        if (contains(banner, "ubuntu"))         votes.push_back({"Linux",   35, "HTTP banner: Ubuntu"});
        if (contains(banner, "debian"))         votes.push_back({"Linux",   35, "HTTP banner: Debian"});
        if (contains(banner, "centos"))         votes.push_back({"Linux",   35, "HTTP banner: CentOS"});
        if (contains(banner, "fedora"))         votes.push_back({"Linux",   35, "HTTP banner: Fedora"});
        if (contains(banner, "win"))            votes.push_back({"Windows", 20, "HTTP banner: Win string"});
    }

    // ── FTP banners ───────────────────────────────────────────────────────
    if (svc == "ftp" || svc == "ftp-data") {
        if (contains(version, "microsoft") ||
            contains(version, "iis"))           votes.push_back({"Windows", 45, "FTP: Microsoft FTP/IIS"});
        if (contains(version, "vsftpd"))        votes.push_back({"Linux",   40, "FTP: vsftpd"});
        if (contains(version, "proftpd"))       votes.push_back({"Linux",   40, "FTP: ProFTPD"});
        if (contains(version, "pureftpd"))      votes.push_back({"Linux",   35, "FTP: Pure-FTPd"});
        if (contains(banner, "filezilla"))      votes.push_back({"Windows", 35, "FTP: FileZilla server"});
    }

    // ── SMTP banners ──────────────────────────────────────────────────────
    if (svc == "smtp" || svc == "smtp-submission") {
        if (contains(version, "postfix"))       votes.push_back({"Linux",   40, "SMTP: Postfix"});
        if (contains(version, "exim"))          votes.push_back({"Linux",   40, "SMTP: Exim"});
        if (contains(version, "sendmail"))      votes.push_back({"Linux",   35, "SMTP: Sendmail"});
        if (contains(version, "exchange") ||
            contains(version, "microsoft"))     votes.push_back({"Windows", 45, "SMTP: Exchange/Microsoft"});
        if (contains(version, "qmail"))         votes.push_back({"Linux",   35, "SMTP: qmail"});
    }

    // ── RDP → Windows ────────────────────────────────────────────────────
    if (svc == "rdp")                           votes.push_back({"Windows", 60, "RDP port open"});

    // ── SMB → Windows (usually) ──────────────────────────────────────────
    if (svc == "smb")                           votes.push_back({"Windows", 40, "SMB port open (may be Samba)"});

    // ── Netbios → Windows ────────────────────────────────────────────────
    if (svc == "netbios-ssn" ||
        svc == "netbios-ns")                    votes.push_back({"Windows", 35, "NetBIOS port open"});

    // ── MSRPC → Windows ──────────────────────────────────────────────────
    if (svc == "msrpc")                         votes.push_back({"Windows", 35, "MSRPC port open"});

    // ── WinRM-like ports ─────────────────────────────────────────────────
    if (r.port == 5985 || r.port == 5986)       votes.push_back({"Windows", 40, "WinRM port open"});

    // ── Typical Linux service ports ───────────────────────────────────────
    if (svc == "mysql" || svc == "postgresql" ||
        svc == "redis" || svc == "mongodb")     votes.push_back({"Linux",   15, "Common Linux DB service"});

    // ── Docker → Linux ────────────────────────────────────────────────────
    if (svc == "docker")                        votes.push_back({"Linux",   30, "Docker API port"});

    return votes;
}

OSGuess BannerOSStrategy::mergeVotes(const std::vector<Vote>& votes) {
    if (votes.empty()) return OSGuess{};

    // Accumulate weight per family
    std::map<std::string, int>    weightMap;
    std::map<std::string, std::vector<std::string>> reasonMap;
    for (const auto& v : votes) {
        weightMap[v.family]   += v.weight;
        reasonMap[v.family].push_back(v.reason);
    }

    // Find the winner
    std::string winner;
    int         winWeight = 0;
    for (const auto& kv : weightMap) {
        if (kv.second > winWeight) { winWeight = kv.second; winner = kv.first; }
    }
    if (winner.empty()) return OSGuess{};

    // Total weight across all families
    int totalWeight = 0;
    for (const auto& kv : weightMap) totalWeight += kv.second;

    // Confidence: winner dominance ratio, scaled to [0,100]
    // Perfect confidence (100) requires the winner to hold ALL evidence.
    double dominance = static_cast<double>(winWeight) / static_cast<double>(totalWeight);
    int conf = static_cast<int>(dominance * 80.0);   // max 80 from votes
    conf     = std::min(conf + winWeight / 4, 90);   // weight bonus, cap at 90
    conf     = std::max(conf, 0);

    // Build reasoning string
    const auto& reasons = reasonMap[winner];
    std::string reasoning;
    for (size_t i = 0; i < reasons.size() && i < 3; ++i) {
        if (i) reasoning += "; ";
        reasoning += reasons[i];
    }
    if (reasons.size() > 3)
        reasoning += " (+" + std::to_string(reasons.size() - 3) + " more)";

    return OSGuess(winner, "", conf, reasoning);
}

OSGuess BannerOSStrategy::analyzeResults(const std::string& ip,
                                          const std::vector<ScanResult>& results) const {
    std::vector<Vote> allVotes;
    for (const auto& r : results) {
        if (r.ip != ip || r.state != PortState::Open) continue;
        auto v = votesFromResult(r);
        for (auto& vote : v) allVotes.push_back(std::move(vote));
    }
    return mergeVotes(allVotes);
}


// ══════════════════════════════════════════════════════════════════════════════
//  TTLFingerprintStrategy
//
//  Stub in M7 — icmpPing() requires CAP_NET_RAW.  Registered so the
//  architecture is complete; returns confidence=0 until M8 adds raw sockets.
// ══════════════════════════════════════════════════════════════════════════════

TTLFingerprintStrategy::TTLFingerprintStrategy(int timeoutMs, Logger& logger)
    : timeoutMs_(timeoutMs)
    , logger_(logger)
{}

OSGuess TTLFingerprintStrategy::analyzeResults(const std::string& ip,
                                                const std::vector<ScanResult>& results) const {
    // Check if any result already has a TTL from a previous probe
    for (const auto& r : results) {
        if (r.ip != ip || r.ttl < 0) continue;
        return ttlToGuess(r.ttl);
    }
    // No TTL data — would need ICMP raw socket (CAP_NET_RAW)
    logger_.debug("TTL strategy: no TTL data for " + ip + " (icmpPing not available)");
    (void)timeoutMs_;
    return OSGuess{};
}

OSGuess TTLFingerprintStrategy::ttlToGuess(int ttl) {
    // Initial TTL values by OS family (RFC standard defaults):
    //   255 → Cisco IOS, Solaris, some BSDs
    //   128 → Windows
    //    64 → Linux, macOS, Android
    //    60 → some HP-UX
    //
    // Routers decrement TTL by 1 per hop. We use threshold ranges.
    if (ttl >= 240) return OSGuess("Cisco/Solaris", "",  65, "TTL >= 240 (initial 255)");
    if (ttl >= 100) return OSGuess("Windows",       "",  60, "TTL >= 100 (initial 128)");
    if (ttl >= 50)  return OSGuess("Linux/macOS",   "",  60, "TTL >= 50  (initial 64)");
    if (ttl >= 40)  return OSGuess("HP-UX",         "",  40, "TTL >= 40  (initial 60)");
    return OSGuess{};
}


// ══════════════════════════════════════════════════════════════════════════════
//  OSDetector
// ══════════════════════════════════════════════════════════════════════════════

void OSDetector::registerStrategy(std::unique_ptr<IFingerprintStrategy> strategy) {
    strategies_.push_back(std::move(strategy));
}

OSGuess OSDetector::detect(const std::string& ip,
                            const std::vector<ScanResult>& results) const {
    std::vector<OSGuess> guesses;
    for (const auto& strat : strategies_) {
        OSGuess g = strat->analyzeResults(ip, results);
        if (g.confidence > 0 && g.osFamily != "Unknown") {
            guesses.push_back(std::move(g));
        }
    }
    return merge(guesses);
}

OSGuess OSDetector::merge(const std::vector<OSGuess>& guesses) {
    if (guesses.empty()) return OSGuess{};
    // Return the highest-confidence guess.
    return *std::max_element(guesses.begin(), guesses.end(),
        [](const OSGuess& a, const OSGuess& b) {
            return a.confidence < b.confidence;
        });
}

std::string OSDetector::guessToString(const OSGuess& g) {
    if (g.confidence == 0 || g.osFamily == "Unknown") return "Unknown";
    std::string s = g.osFamily;
    if (!g.osVersion.empty()) s += " " + g.osVersion;
    s += "  (confidence: " + std::to_string(g.confidence) + "%)";
    return s;
}

}  // namespace rhs
