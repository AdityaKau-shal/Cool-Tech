#!/usr/bin/env python3
"""
Cool-Tech Cybersecurity Toolkit
A collection of practical cybersecurity utilities.
"""

import hashlib
import base64
import socket
import string
import re
import argparse
import sys


# ── Password Strength Analyzer ────────────────────────────────────────────────

def analyze_password(password: str) -> dict:
    """
    Analyze the strength of a password and return a report.

    Returns a dict with keys:
        score   - integer 0-5
        level   - "Very Weak" / "Weak" / "Fair" / "Strong" / "Very Strong"
        checks  - dict of individual criterion results
    """
    checks = {
        "length_8":    len(password) >= 8,
        "length_12":   len(password) >= 12,
        "uppercase":   bool(re.search(r"[A-Z]", password)),
        "lowercase":   bool(re.search(r"[a-z]", password)),
        "digits":      bool(re.search(r"\d", password)),
        "special":     bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    score = sum([
        checks["length_8"],
        checks["length_12"],
        checks["uppercase"],
        checks["digits"],
        checks["special"],
    ])

    levels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    level = levels[min(score, len(levels) - 1)]

    return {"score": score, "level": level, "checks": checks}


# ── Hash Generator ─────────────────────────────────────────────────────────────

SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")

# Algorithms that are cryptographically broken and should not be used for
# security-sensitive operations (e.g. password storage, digital signatures).
_DEPRECATED_ALGORITHMS = {"md5", "sha1"}


def generate_hash(data: str, algorithm: str = "sha256") -> str:
    """
    Return the hex digest of *data* using the specified *algorithm*.

    MD5 and SHA-1 are supported for legacy/educational use only.
    A DeprecationWarning is emitted when they are selected.

    Raises ValueError for unsupported algorithms.
    """
    import warnings

    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Choose from: {', '.join(SUPPORTED_ALGORITHMS)}"
        )
    if algorithm in _DEPRECATED_ALGORITHMS:
        warnings.warn(
            f"{algorithm.upper()} is cryptographically broken and should not be used "
            "for security-sensitive operations. Prefer SHA-256 or SHA-512.",
            DeprecationWarning,
            stacklevel=2,
        )
    h = hashlib.new(algorithm)
    h.update(data.encode("utf-8"))
    return h.hexdigest()


# ── Caesar Cipher ─────────────────────────────────────────────────────────────

def caesar_cipher(text: str, shift: int, mode: str = "encrypt") -> str:
    """
    Encrypt or decrypt *text* using a Caesar cipher with the given *shift*.

    Non-alphabetic characters are left unchanged.
    *mode* must be 'encrypt' or 'decrypt'.
    """
    if mode not in ("encrypt", "decrypt"):
        raise ValueError("mode must be 'encrypt' or 'decrypt'")

    effective_shift = shift % 26
    if mode == "decrypt":
        effective_shift = -effective_shift

    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + effective_shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


# ── Base64 Encoder / Decoder ──────────────────────────────────────────────────

def base64_encode(data: str) -> str:
    """Return the Base64-encoded representation of *data*."""
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def base64_decode(data: str) -> str:
    """
    Decode a Base64-encoded string.

    Raises ValueError if *data* is not valid Base64.
    """
    try:
        return base64.b64decode(data.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Invalid Base64 input: {exc}") from exc


# ── Port Scanner ───────────────────────────────────────────────────────────────

def scan_ports(host: str, ports: list[int], timeout: float = 1.0) -> dict:
    """
    Scan a list of TCP *ports* on *host*.

    Returns a dict mapping each port to True (open) or False (closed/filtered).
    """
    results = {}
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results[port] = True
        except (socket.timeout, ConnectionRefusedError, OSError):
            results[port] = False
    return results


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersec_toolkit",
        description="Cool-Tech Cybersecurity Toolkit",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # password
    pw = sub.add_parser("password", help="Analyze password strength")
    pw.add_argument("password", help="Password to analyze")

    # hash
    h = sub.add_parser("hash", help="Generate a cryptographic hash")
    h.add_argument("data", help="Data to hash")
    h.add_argument(
        "--algo",
        default="sha256",
        choices=SUPPORTED_ALGORITHMS,
        help="Hash algorithm (default: sha256)",
    )

    # caesar
    c = sub.add_parser("caesar", help="Caesar cipher encrypt/decrypt")
    c.add_argument("text", help="Text to process")
    c.add_argument("shift", type=int, help="Shift value (1-25)")
    c.add_argument(
        "--mode",
        default="encrypt",
        choices=("encrypt", "decrypt"),
        help="Operation mode (default: encrypt)",
    )

    # base64
    b = sub.add_parser("base64", help="Base64 encode/decode")
    b.add_argument("data", help="Data to process")
    b.add_argument(
        "--mode",
        default="encode",
        choices=("encode", "decode"),
        help="Operation mode (default: encode)",
    )

    # portscan
    ps = sub.add_parser("portscan", help="Scan TCP ports on a host")
    ps.add_argument("host", help="Target hostname or IP address")
    ps.add_argument(
        "ports",
        help="Comma-separated list of ports or range (e.g. 22,80,443 or 1-1024)",
    )
    ps.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )

    return parser


def _parse_ports(ports_str: str) -> list[int]:
    """Parse a port spec like '22,80,443' or '1-1024' into a list of ints."""
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "password":
        report = analyze_password(args.password)
        print(f"Password strength: {report['level']} (score {report['score']}/5)")
        for criterion, passed in report["checks"].items():
            status = "✓" if passed else "✗"
            print(f"  {status} {criterion.replace('_', ' ')}")

    elif args.command == "hash":
        digest = generate_hash(args.data, args.algo)
        print(f"{args.algo.upper()}: {digest}")

    elif args.command == "caesar":
        result = caesar_cipher(args.text, args.shift, args.mode)
        print(result)

    elif args.command == "base64":
        if args.mode == "encode":
            print(base64_encode(args.data))
        else:
            try:
                print(base64_decode(args.data))
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                sys.exit(1)

    elif args.command == "portscan":
        try:
            ports = _parse_ports(args.ports)
        except ValueError:
            print("Error: invalid port specification.", file=sys.stderr)
            sys.exit(1)

        print(f"Scanning {args.host} ...")
        results = scan_ports(args.host, ports, timeout=args.timeout)
        open_ports = [p for p, s in results.items() if s]
        closed_ports = [p for p, s in results.items() if not s]
        if open_ports:
            print(f"  Open ports:   {', '.join(str(p) for p in sorted(open_ports))}")
        if closed_ports:
            print(f"  Closed ports: {', '.join(str(p) for p in sorted(closed_ports))}")
        if not open_ports:
            print("  No open ports found.")


if __name__ == "__main__":
    main()
