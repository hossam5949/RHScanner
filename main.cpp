// ──────────────────────────────────────────────────────────────────────────────
//  main.cpp
//
//  Entry point for RH Scanner.
//
//  Responsibility (intentionally thin):
//    1. Print the banner.
//    2. Short-circuit --help / --version before any parsing.
//    3. Parse command-line arguments → ScanConfig.
//    4. Construct shared infrastructure (ResultStore, Logger, OutputFormatter).
//    5. Time and drive Scanner::run().
//    6. Pass results to OutputFormatter for final display.
// ──────────────────────────────────────────────────────────────────────────────

#include "os/os.h"
#include "scanner/scanner.h"
#include "service/service.h"
#include "threading/threading.h"
#include "utils/utils.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {

    // ── 1. Banner ──────────────────────────────────────────────────────────
    rhs::OutputFormatter fmt;
    fmt.printBanner();

    // ── 2. Short-circuit flags that bypass argument parsing ────────────────
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            rhs::OutputFormatter::printHelp();
            return EXIT_SUCCESS;
        }
        if (arg == "--version") {
            std::cout << "rhscanner 0.1.0\n";
            return EXIT_SUCCESS;
        }
    }

    // ── 3. Argument parsing ────────────────────────────────────────────────
    rhs::ArgumentParser parser;
    rhs::ScanConfig     cfg = parser.parse(argc, argv);

    // ── 4. Infrastructure ──────────────────────────────────────────────────
    rhs::Logger          logger(cfg.verbosity);
    rhs::ResultStore     store;
    rhs::OutputFormatter output(cfg.verbosity);

    // ── 5. Run scan (timed) ────────────────────────────────────────────────
    auto t0 = std::chrono::steady_clock::now();

    rhs::Scanner scanner(cfg, store, logger);
    scanner.run();

    auto t1      = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    // ── 6. Display results ─────────────────────────────────────────────────
    auto results  = store.getResults();
    int  openCount = 0;
    for (const auto& r : results) {
        if (r.state == rhs::PortState::Open) { ++openCount; }
    }

    output.printResults(results);
    output.printScanSummary(openCount,
                            static_cast<int>(results.size()),
                            elapsed);

    return EXIT_SUCCESS;
}
