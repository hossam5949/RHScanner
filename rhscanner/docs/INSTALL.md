# Installation Guide

## Supported Platforms

RH Scanner is currently supported on:

* Kali Linux
* Ubuntu
* Debian-based Linux distributions

---

## Requirements

Before building RH Scanner, install the required packages.

### Kali Linux

```bash
sudo apt update
sudo apt install -y build-essential cmake git
```

### Ubuntu

```bash
sudo apt update
sudo apt install -y build-essential cmake git
```

---

## Verify Installation

Check GCC:

```bash
g++ --version
```

Check CMake:

```bash
cmake --version
```

---

## Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/RHScanner.git
cd RHScanner
```

---

## Build Project

Clean old build files:

```bash
make clean
```

Compile:

```bash
make
```

Expected output:

```text
[100%] Built target rhscanner
Built: ./rhscanner (release)
```

---

## Running RH Scanner

Display help:

```bash
./build/release/rhscanner --help
```

Run a basic scan:

```bash
./build/release/rhscanner -H 8.8.8.8 -P 53
```

---

## Troubleshooting

### CMake Not Found

Install CMake:

```bash
sudo apt install cmake
```

---

### Permission Denied

Make the binary executable:

```bash
chmod +x ./build/release/rhscanner
```

---

### Build Directory Issues

Remove build artifacts:

```bash
rm -rf build
make
```

---

### DNS Resolution Problems

Verify internet connectivity:

```bash
ping google.com
```

Check DNS configuration:

```bash
cat /etc/resolv.conf
```

---

## Recommended Environment

* Kali Linux 2024+
* GCC 13+
* CMake 3.20+
* 4+ CPU cores for optimal multi-threaded performance
