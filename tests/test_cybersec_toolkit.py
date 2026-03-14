"""Tests for Cool-Tech Cybersecurity Toolkit."""

import pytest
from cybersec_toolkit import (
    analyze_password,
    generate_hash,
    caesar_cipher,
    base64_encode,
    base64_decode,
    scan_ports,
    main,
)


# ── analyze_password ──────────────────────────────────────────────────────────

class TestAnalyzePassword:
    def test_very_weak_short(self):
        report = analyze_password("abc")
        assert report["score"] == 0
        assert report["level"] == "Very Weak"

    def test_weak_only_lowercase(self):
        report = analyze_password("abcdefgh")
        # length_8 passes → score 1
        assert report["score"] == 1
        assert report["level"] == "Weak"

    def test_fair_lowercase_and_digits(self):
        report = analyze_password("abcdefg1")
        # length_8 + digits → score 2
        assert report["score"] == 2
        assert report["level"] == "Fair"

    def test_strong_password(self):
        # length_8 + uppercase + digits (no special, no length_12) → score 3
        report = analyze_password("Abcdefg1")
        assert report["score"] == 3
        assert report["level"] == "Strong"

    def test_very_strong_password(self):
        report = analyze_password("Abcdefghij1!")
        # length_8 + length_12 + uppercase + digits + special → score 5
        assert report["score"] == 5
        assert report["level"] == "Very Strong"

    def test_checks_keys_present(self):
        report = analyze_password("password")
        expected_keys = {"length_8", "length_12", "uppercase", "lowercase", "digits", "special"}
        assert set(report["checks"].keys()) == expected_keys

    def test_empty_password(self):
        report = analyze_password("")
        assert report["score"] == 0
        assert report["level"] == "Very Weak"


# ── generate_hash ─────────────────────────────────────────────────────────────

class TestGenerateHash:
    def test_sha256_known_value(self):
        # echo -n "hello" | sha256sum
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert generate_hash("hello", "sha256") == expected

    def test_md5_known_value(self):
        expected = "5d41402abc4b2a76b9719d911017c592"
        assert generate_hash("hello", "md5") == expected

    def test_sha1_known_value(self):
        expected = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert generate_hash("hello", "sha1") == expected

    def test_sha512_non_empty(self):
        result = generate_hash("hello", "sha512")
        assert len(result) == 128

    def test_default_algorithm_is_sha256(self):
        assert generate_hash("hello") == generate_hash("hello", "sha256")

    def test_algorithm_case_insensitive(self):
        assert generate_hash("hello", "SHA256") == generate_hash("hello", "sha256")

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            generate_hash("hello", "blake2b")

    def test_md5_emits_deprecation_warning(self):
        with pytest.warns(DeprecationWarning, match="cryptographically broken"):
            generate_hash("hello", "md5")

    def test_sha1_emits_deprecation_warning(self):
        with pytest.warns(DeprecationWarning, match="cryptographically broken"):
            generate_hash("hello", "sha1")

    def test_sha256_no_deprecation_warning(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            generate_hash("hello", "sha256")  # must not raise


# ── caesar_cipher ─────────────────────────────────────────────────────────────

class TestCaesarCipher:
    def test_encrypt_basic(self):
        assert caesar_cipher("abc", 1, "encrypt") == "bcd"

    def test_decrypt_basic(self):
        assert caesar_cipher("bcd", 1, "decrypt") == "abc"

    def test_roundtrip(self):
        original = "Hello, World!"
        encrypted = caesar_cipher(original, 13, "encrypt")
        assert caesar_cipher(encrypted, 13, "decrypt") == original

    def test_preserves_case(self):
        assert caesar_cipher("ABC", 1, "encrypt") == "BCD"

    def test_non_alpha_unchanged(self):
        assert caesar_cipher("abc 123!", 3, "encrypt") == "def 123!"

    def test_wrap_around(self):
        assert caesar_cipher("xyz", 3, "encrypt") == "abc"

    def test_shift_26_is_identity(self):
        assert caesar_cipher("Hello", 26, "encrypt") == "Hello"

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="mode must be"):
            caesar_cipher("abc", 1, "bad_mode")


# ── base64 ────────────────────────────────────────────────────────────────────

class TestBase64:
    def test_encode_known_value(self):
        assert base64_encode("Hello, World!") == "SGVsbG8sIFdvcmxkIQ=="

    def test_decode_known_value(self):
        assert base64_decode("SGVsbG8sIFdvcmxkIQ==") == "Hello, World!"

    def test_roundtrip(self):
        original = "Cool-Tech cybersecurity toolkit!"
        assert base64_decode(base64_encode(original)) == original

    def test_invalid_base64_raises(self):
        with pytest.raises(ValueError, match="Invalid Base64"):
            base64_decode("not_valid_base64!!!")


# ── scan_ports ────────────────────────────────────────────────────────────────

class TestScanPorts:
    def test_open_port(self):
        """A port with a listening server should be detected as open."""
        import socket
        import threading

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                conn, _ = server.accept()
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        results = scan_ports("127.0.0.1", [port], timeout=2.0)
        assert results[port] is True

    def test_closed_port(self):
        """A port with nothing listening should be closed."""
        results = scan_ports("127.0.0.1", [19999], timeout=0.5)
        assert results[19999] is False

    def test_returns_all_requested_ports(self):
        results = scan_ports("127.0.0.1", [19998, 19997], timeout=0.5)
        assert set(results.keys()) == {19998, 19997}


# ── CLI ────────────────────────────────────────────────────────────────────────

class TestCLI:
    def test_hash_command(self, capsys):
        main(["hash", "hello"])
        captured = capsys.readouterr()
        assert "SHA256" in captured.out
        assert "2cf24dba" in captured.out

    def test_hash_command_md5(self, capsys):
        main(["hash", "hello", "--algo", "md5"])
        captured = capsys.readouterr()
        assert "MD5" in captured.out

    def test_caesar_encrypt_command(self, capsys):
        main(["caesar", "abc", "1"])
        captured = capsys.readouterr()
        assert captured.out.strip() == "bcd"

    def test_caesar_decrypt_command(self, capsys):
        main(["caesar", "bcd", "1", "--mode", "decrypt"])
        captured = capsys.readouterr()
        assert captured.out.strip() == "abc"

    def test_base64_encode_command(self, capsys):
        main(["base64", "Hello"])
        captured = capsys.readouterr()
        assert captured.out.strip() == "SGVsbG8="

    def test_base64_decode_command(self, capsys):
        main(["base64", "SGVsbG8=", "--mode", "decode"])
        captured = capsys.readouterr()
        assert captured.out.strip() == "Hello"

    def test_password_command(self, capsys):
        main(["password", "Abcdefghij1!"])
        captured = capsys.readouterr()
        assert "Very Strong" in captured.out
