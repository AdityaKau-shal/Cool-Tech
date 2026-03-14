# Cool-Tech Cybersecurity Toolkit

A lightweight, zero-dependency Python cybersecurity toolkit you can run straight from the command line.

## Features

| Tool | Description |
|------|-------------|
| **Password Analyzer** | Score & level (Very Weak → Very Strong) with per-criterion feedback |
| **Hash Generator** | MD5, SHA-1, SHA-256, SHA-512 digests |
| **Caesar Cipher** | Encrypt or decrypt text with a configurable shift |
| **Base64** | Encode and decode Base64 strings |
| **Port Scanner** | TCP port scan with configurable timeout |

## Requirements

Python 3.10+. No third-party packages required.

## Usage

```bash
python cybersec_toolkit.py <command> [options]
```

### Password Analyzer

```bash
python cybersec_toolkit.py password "MyP@ssw0rd123"
# Password strength: Very Strong (score 5/5)
#   ✓ length 8
#   ✓ length 12
#   ✓ uppercase
#   ✓ digits
#   ✓ special
```

### Hash Generator

```bash
python cybersec_toolkit.py hash "hello world"
python cybersec_toolkit.py hash "hello world" --algo md5
python cybersec_toolkit.py hash "hello world" --algo sha512
```

Supported algorithms: `md5`, `sha1`, `sha256` (default), `sha512`.

### Caesar Cipher

```bash
# Encrypt
python cybersec_toolkit.py caesar "Hello, World!" 13
# Uryyb, Jbeyq!

# Decrypt
python cybersec_toolkit.py caesar "Uryyb, Jbeyq!" 13 --mode decrypt
# Hello, World!
```

### Base64 Encode / Decode

```bash
python cybersec_toolkit.py base64 "Cool-Tech"
# Q29vbC1UZWNo

python cybersec_toolkit.py base64 "Q29vbC1UZWNo" --mode decode
# Cool-Tech
```

### Port Scanner

```bash
# Scan specific ports
python cybersec_toolkit.py portscan 127.0.0.1 22,80,443

# Scan a range
python cybersec_toolkit.py portscan 127.0.0.1 1-1024 --timeout 0.5
```

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```
