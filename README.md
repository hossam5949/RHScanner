# RH Scanner

RH Scanner is a multi-threaded network scanner written in C++17 using POSIX sockets on Linux.

The project was built from scratch as a practical networking and cybersecurity learning project to gain hands-on experience with:

* Socket Programming
* TCP Networking
* Multi-threading
* DNS Resolution
* Service Detection
* Banner Grabbing
* Version Detection
* Passive OS Fingerprinting

---

## Features

### Core Scanning

* TCP Connect Scanning
* Single Host Scanning
* Hostname Scanning
* CIDR Range Scanning
* IP Range Scanning
* Port Range Scanning

### Performance

* Multi-threaded Architecture
* Configurable Thread Count
* Concurrent Port Scanning
* Custom Connection Timeouts

### Detection

* Service Detection
* Banner Grabbing
* Version Detection
* Passive OS Detection

### DNS Support

* Hostname Resolution using `getaddrinfo()`
* Support for domains such as:

  * google.com
  * github.com
  * scanme.nmap.org

---

## Project Structure

```text
main.cpp
scanner/
service/
threading/
os/
utils/
```

---

## Build

### Requirements

* Linux
* GCC with C++17 support
* CMake
* POSIX Threads

### Compile

```bash
make clean
make
```

---

## Usage

Scan a single host:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 53
```

Scan a hostname:

```bash
./build/release/rhscanner -H google.com -P 80,443
```

Service detection:

```bash
./build/release/rhscanner -H scanme.nmap.org -P 22 -S
```

Full reconnaissance:

```bash
./build/release/rhscanner -RH scanme.nmap.org -T 500
```

---

## Example Output

```text
45.33.32.156    22    open    ssh     OpenSSH_6.6.1p1
45.33.32.156    80    open    http    Apache/2.4.7 (Ubuntu)

OS Detection Results

OS Guess   : Linux
Confidence : 90%
```

---

## Current Capabilities

* TCP Connect Scan
* DNS Resolution
* Multi-threaded Scanning
* Service Detection
* Banner Grabbing
* Version Detection
* Passive OS Detection

---

## Limitations

* TCP Connect Scan only
* No SYN Scan
* No UDP Scan
* No IPv6 Support
* No NSE-style Scripting Engine
* Passive OS Detection only

---

## Future Roadmap

* UDP Scanning
* SYN Scanning
* IPv6 Support
* JSON Export
* CSV Export
* Improved Fingerprinting
* Better Reporting

---

## Educational Purpose

This project was developed for educational purposes and authorized security testing only.

---

## Author

Hossam Elsemelawy

Built with C++17, POSIX Sockets, and Linux.
