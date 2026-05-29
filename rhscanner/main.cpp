// ──────────────────────────────────────────────────────────────────────────────
//  main.cpp
//
//  Entry point for RH Scanner.
//
//  Responsibility:
//    1. Print the banner.
//    2. Parse command-line arguments into a ScanConfig.
//    3. Construct shared infrastructure (ResultStore, Logger, OutputFormatter).
//    4. Hand control to Scanner::run().
//    5. Pass results to OutputFormatter for final display.
//
//  main() must remain thin — all logic belongs in the module that owns it.
// ──────────────────────────────────────────────────────────────────────────────

#include "os/os.h"
#include "scanner/scanner.h"
#include "service/service.h"
#include "threading/threading.h"
#include "utils/utils.h"

#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    // ── 1. Banner ──────────────────────────────────────────────────────────
    rhs::OutputFormatter fmt;
    fmt.printBanner();

    // ── 2. Short-circuit flags that need no scan ───────────────────────────
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
    rhs::Logger      logger(cfg.verbosity);
    rhs::ResultStore store;

    rhs::OutputFormatter output(cfg.verbosity);

    // ── 5. Run scan ────────────────────────────────────────────────────────
    //
    // TODO (M3): Scanner::run() will block here until all probes finish.
    //
    rhs::Scanner scanner(cfg, store, logger);
    scanner.run();

    // ── 6. Display results ─────────────────────────────────────────────────
    //
    // TODO (M3): populate results and call printResults().
    //
    auto results = store.getResults();
    output.printResults(results);

    // ── 7. Summary ─────────────────────────────────────────────────────────
    //
    // TODO (M7): compute elapsed time and call printScanSummary().
    //
    output.printScanSummary(0, 0, 0.0);

    return EXIT_SUCCESS;
}
