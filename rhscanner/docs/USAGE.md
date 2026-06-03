# RH Scanner Usage Guide

## Command Syntax

```bash
./build/release/rhscanner [OPTIONS]
```

---

# Target Selection

## -H <host>

Specify a target host.

Supports:

* Single IPv4
* Hostnames
* CIDR ranges
* Last-octet IP ranges

Examples:

```bash
./build/release/rhscanner -H 192.168.1.10 -P
./build/release/rhscanner -H google.com -P 80,443
./build/release/rhscanner -H scanme.nmap.org -P 22
```

---

## CIDR Range

```bash
./build/release/rhscanner -H 192.168.1.0/24 -P 80
```

Scans all usable hosts inside the subnet.

---

## Last-Octet Range

```bash
./build/release/rhscanner -H 192.168.1.1-20 -P 22
```

Scans hosts:

```text
192.168.1.1
...
192.168.1.20
```

---

# Scan Types

## -P

Enable port scanning.

Default range:

```text
1-1024
```

Example:

```bash
./build/release/rhscanner -H 8.8.8.8 -P
```

---

## -P <port>

Single port:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 53
```

---

## -P <start-end>

Port range:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 20-100
```

---

## -P <csv>

Multiple ports:

```bash
./build/release/rhscanner -H scanme.nmap.org -P 22,80,443
```

---

## -S

Enable:

* Service Detection
* Banner Grabbing
* Version Detection

Example:

```bash
./build/release/rhscanner -H scanme.nmap.org -P 22 -S
```

Example Output:

```text
22 open ssh OpenSSH_6.6.1p1
```

---

## -O

Enable passive operating system detection.

Example:

```bash
./build/release/rhscanner -H scanme.nmap.org -P 22,80 -S -O
```

Example Output:

```text
OS Guess   : Linux
Confidence : 90%
```

---

## -RH

Full reconnaissance mode.

Automatically enables:

* Port Scan
* Service Detection
* Banner Grabbing
* Version Detection
* OS Detection

Example:

```bash
./build/release/rhscanner -RH scanme.nmap.org
```

---

# Performance

## -T <threads>

Thread count.

Default:

```text
50
```

Maximum:

```text
500
```

Examples:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 1-100 -T 1
./build/release/rhscanner -H 8.8.8.8 -P 1-100 -T 100
./build/release/rhscanner -H 8.8.8.8 -P 1-100 -T 500
```

---

## --timeout <ms>

Per-probe timeout.

Default:

```text
1000 ms
```

Examples:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 53 --timeout 500
./build/release/rhscanner -H 8.8.8.8 -P 53 --timeout 2000
```

---

# Verbosity

## -v

Show additional information.

Example:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 53 -v
```

---

## -vv

Debug mode.

Shows internal socket operations.

Example:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 53 -vv
```

---

# Miscellaneous

## --help

Display help screen.

```bash
./build/release/rhscanner --help
```

---

## --version

Display version information.

```bash
./build/release/rhscanner --version
```

---

# Example Workflows

## Basic Port Scan

```bash
./build/release/rhscanner -H 8.8.8.8 -P 53
```

---

## Service Detection

```bash
./build/release/rhscanner -H scanme.nmap.org -P 22 -S
```

---

## Full Reconnaissance

```bash
./build/release/rhscanner -RH scanme.nmap.org -T 500
```

---

## Network Scan

```bash
./build/release/rhscanner -H 192.168.1.0/24 -P 80 -T 200
```

---

## Fast DNS Scan

```bash
./build/release/rhscanner -H google.com -P 80,443
```
