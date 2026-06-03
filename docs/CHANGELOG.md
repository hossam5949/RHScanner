# Changelog

All notable changes to RH Scanner will be documented in this file.

---

# v1.0.0 (M6 + M7)

Release Date: 2026

## Added

* Hostname support via getaddrinfo()
* Banner Grabbing
* Version Detection
* Passive OS Detection
* Banner-based OS Fingerprinting
* TTL-based OS Fingerprinting
* Improved Output Formatting
* Professional Project Documentation

## Service Detection

* SSH Detection
* HTTP Detection
* HTTPS Detection
* DNS Detection
* FTP Detection
* SMTP Detection
* POP3 Detection
* IMAP Detection

## OS Detection

* Linux Identification
* Windows Identification
* Cisco IOS Identification
* Confidence Scoring
* Detection Reasoning

## Documentation

* README.md
* INSTALL.md
* USAGE.md
* ARCHITECTURE.md
* PROJECT_TREE.md

---

# v0.5.0 (M4 + M5)

## Added

* ThreadPool Implementation
* WorkQueue Implementation
* Parallel Scanning Engine
* Service Detection Framework
* Port-to-Service Mapping
* Multi-threaded Scan Execution

## Performance

### Before

```text
100 ports
1 thread
~99 seconds
```

### After

```text
100 ports
50 threads
~2 seconds
```

---

# v0.3.0 (M3)

## Added

* TCP Connect Scanning
* ProbeEngine
* ResultStore
* Scan Results Output
* Timeout Handling

## Scanner

* Open Port Detection
* Closed Port Detection
* Filtered Port Detection

---

# v0.2.0 (M2)

## Added

* ArgumentParser
* IPRange Parser
* PortRange Parser
* CIDR Support
* Range Support
* Validation System

## Fixed

* uint16_t overflow bug in port range processing
* Port range infinite loop edge cases
* Parser validation issues

---

# v0.1.0 (M1)

Initial Project Skeleton

## Added

* Project Architecture
* Build System
* CMake Configuration
* Makefile
* Scanner Module Skeleton
* Threading Module Skeleton
* Service Module Skeleton
* OS Module Skeleton
* Utility Module Skeleton

## Notes

First working project structure created.
