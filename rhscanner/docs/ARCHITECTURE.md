# RH Scanner Architecture

## Overview

RH Scanner is a modular multi-threaded network scanner written in C++17.

The project is divided into independent components responsible for:

* Argument Parsing
* Host Resolution
* Port Scanning
* Thread Management
* Service Detection
* Banner Grabbing
* OS Detection
* Result Storage
* Output Formatting

The architecture was designed to keep networking, detection, threading, and presentation logic separated.

---

# High-Level Data Flow

```text
User Input
    |
    v
ArgumentParser
    |
    v
HostResolver
    |
    v
Scanner
    |
    v
ThreadPool
    |
    v
ProbeEngine
    |
    v
ResultStore
    |
    +--------------------+
    |                    |
    v                    v
ServiceDetector      OSDetector
    |                    |
    +---------+----------+
              |
              v
      OutputFormatter
```

---

# Core Modules

## main.cpp

Responsibilities:

* Application entry point
* Banner display
* Parse command-line arguments
* Create scanner instance
* Start scanning process
* Print final results

main.cpp intentionally contains minimal business logic.

---

## utils/

Responsibilities:

* Argument parsing
* Host parsing
* Port parsing
* DNS resolution
* Logging
* Output formatting
* Result storage

Files:

```text
utils.h
utils.cpp
```

Key Classes:

* ArgumentParser
* HostResolver
* IPRange
* PortRange
* Logger
* ResultStore
* OutputFormatter

---

# Scanner Module

Location:

```text
scanner/
```

Files:

```text
scanner.h
scanner.cpp
```

Responsibilities:

* Build scan task list
* Coordinate scan execution
* Manage scan lifecycle
* Execute post-processing

Main Classes:

## ProbeEngine

Responsible for:

* TCP connection attempts
* Timeout handling
* Banner collection

Methods:

```cpp
tcpConnect()
grabBanner()
```

---

## Scanner

Responsible for:

* Building scan tasks
* Scheduling work
* Collecting results
* Triggering detection modules

---

# ThreadPool Module

Location:

```text
threading/
```

Files:

```text
threading.h
threading.cpp
```

Responsibilities:

* Parallel execution
* Work scheduling
* Thread synchronization

Main Components:

## WorkQueue

Thread-safe task queue.

Provides:

```cpp
push()
pop()
setDone()
```

---

## ThreadPool

Responsible for:

* Worker creation
* Task execution
* Worker shutdown

Benefits:

* Significant speed improvement
* Efficient utilization of CPU resources
* Concurrent network operations

---

# Service Detection Module

Location:

```text
service/
```

Files:

```text
service.h
service.cpp
```

Responsibilities:

* Service identification
* Version extraction
* Banner analysis

Examples:

```text
22  -> ssh
80  -> http
443 -> https
53  -> dns
```

Main Class:

## ServiceDetector

Provides:

```cpp
detectService()
grabBanner()
parseVersion()
```

---

# Banner Grabbing

Banner grabbing is performed only on open ports.

Process:

```text
Open Port
    |
    v
TCP Connect
    |
    v
Receive Banner
    |
    v
Extract Version Information
```

Examples:

```text
SSH-2.0-OpenSSH_6.6.1p1
```

```text
Server: Apache/2.4.7 (Ubuntu)
```

---

# OS Detection Module

Location:

```text
os/
```

Files:

```text
os.h
os.cpp
```

Responsibilities:

* Passive operating system identification
* TTL analysis
* Banner-based fingerprinting

---

## TTL Fingerprinting

Common initial TTL values:

| OS        | Default TTL |
| --------- | ----------- |
| Linux     | 64          |
| Windows   | 128         |
| Cisco IOS | 255         |

---

## Banner Fingerprinting

Examples:

```text
OpenSSH + Ubuntu
```

→ Linux

```text
Microsoft IIS
```

→ Windows

```text
Apache
```

→ Linux / Unix

---

# ResultStore

Responsibilities:

* Store scan results
* Update service information
* Store OS guesses
* Provide sorted output

ResultStore acts as the central data repository shared by all modules.

---

# Design Decisions

## Why TCP Connect Scanning?

Advantages:

* Simple implementation
* No raw sockets required
* No root privileges required
* Reliable results

Tradeoff:

* Slower than SYN scanning

---

## Why Multi-threading?

Scanning is primarily I/O bound.

Most execution time is spent waiting for:

```text
connect()
```

Using multiple threads allows many connection attempts to occur simultaneously.

Example:

```text
Single Thread  -> ~99 seconds
50 Threads     -> ~2 seconds
```

---

## Why getaddrinfo()?

Provides:

* DNS Resolution
* IPv4 support
* Thread-safe implementation
* Standard POSIX API

---

# Current Limitations

* TCP Connect Scan only
* No UDP support
* No IPv6 support
* No SYN Scan
* Passive OS Detection only

---

# Future Improvements

* SYN Scanning
* UDP Scanning
* IPv6 Support
* JSON Output
* XML Output
* Advanced Fingerprinting
* Exportable Reports
