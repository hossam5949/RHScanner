# Project Structure

This document describes the RH Scanner project layout and the purpose of each component.

## Directory Tree

```text
RHScanner/
├── build/
│   └── release/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CHANGELOG.md
│   ├── INSTALL.md
│   ├── PROJECT_TREE.md
│   └── USAGE.md
├── LICENSE
├── README.md
├── CMakeLists.txt
├── Makefile
├── main.cpp
├── rhscanner
├── scanner/
│   ├── scanner.cpp
│   └── scanner.h
├── service/
│   ├── service.cpp
│   └── service.h
├── threading/
│   ├── threading.cpp
│   └── threading.h
├── os/
│   ├── os.cpp
│   └── os.h
└── utils/
    ├── utils.cpp
    └── utils.h
```

---

## Root Files

### README.md

Main project documentation.

Contains:

* Overview
* Features
* Build instructions
* Usage examples
* Roadmap

---

### LICENSE

Project license information.

---

### CMakeLists.txt

Primary CMake build configuration.

Responsible for:

* Compiler configuration
* Source file registration
* Build target creation

---

### Makefile

Convenience wrapper around CMake.

Provides:

```bash
make
make clean
make debug
```

---

### main.cpp

Application entry point.

Responsibilities:

* Display banner
* Parse arguments
* Create scanner
* Start scan
* Print results

---

## scanner/

Core scanning engine.

### scanner.h

Public scanner interfaces.

Contains:

* Scanner
* ProbeEngine
* ScanTask

### scanner.cpp

Scanner implementation.

Contains:

* TCP connect scanning
* Task scheduling
* Banner collection
* Scan coordination

---

## service/

Service and version detection.

### service.h

Service detection interfaces.

### service.cpp

Service detection implementation.

Responsible for:

* Port-to-service mapping
* Banner parsing
* Version extraction

Examples:

```text
22  -> ssh
80  -> http
443 -> https
53  -> dns
```

---

## threading/

Parallel execution layer.

### threading.h

Threading interfaces.

Contains:

* WorkQueue
* ThreadPool

### threading.cpp

ThreadPool implementation.

Responsibilities:

* Worker creation
* Task execution
* Synchronization

---

## os/

Operating system fingerprinting.

### os.h

OS detection interfaces.

### os.cpp

OS detection implementation.

Methods:

* TTL fingerprinting
* Banner fingerprinting
* Confidence calculation

---

## utils/

Shared utility functionality.

### utils.h

Utility declarations.

Contains:

* ArgumentParser
* HostResolver
* IPRange
* PortRange
* Logger
* ResultStore
* OutputFormatter

### utils.cpp

Utility implementations.

Responsibilities:

* DNS resolution
* Parsing
* Validation
* Result formatting

---

## docs/

Project documentation.

### INSTALL.md

Installation instructions.

### USAGE.md

Command-line reference.

### ARCHITECTURE.md

Technical design document.

### CHANGELOG.md

Version history.

### PROJECT_TREE.md

Project structure documentation.

---

## build/

Generated build artifacts.

Not intended for manual editing.

Contains:

* CMake cache
* Object files
* Executables

---

## Architectural Philosophy

RH Scanner follows a modular design.

Each subsystem is isolated and responsible for a single area of functionality:

* Scanning
* Threading
* Detection
* Utilities
* Presentation

This separation improves maintainability, testing, and future extensibility.
