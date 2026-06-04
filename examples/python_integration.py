#!/usr/bin/env python3
"""
examples/python_integration.py

Demonstrates calling HLSE Core from Python via ctypes:
  - hlse_check_url        URL phishing detection
  - hlse_check_text       text scam detection
  - hlse_version          library version

No third-party packages — only the standard library.
"""

import ctypes
import os
import sys


def find_lib():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "libhlse.so"),
        os.path.join(here, "libhlse.so"),
        os.path.expanduser("~/.local/lib/libhlse.so"),
        "/usr/local/lib/libhlse.so",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    raise RuntimeError("libhlse.so not found. Run `make` first.")


lib = ctypes.CDLL(find_lib())


class TextVerdict(ctypes.Structure):
    _fields_ = [
        ("score", ctypes.c_int),
        ("n_reasons", ctypes.c_int),
        ("reasons", (ctypes.c_char * 192) * 16),
    ]


class UrlVerdict(ctypes.Structure):
    _fields_ = [
        ("score", ctypes.c_int),
        ("n_reasons", ctypes.c_int),
        ("reasons", (ctypes.c_char * 128) * 12),
    ]


lib.hlse_check_text.restype = TextVerdict
lib.hlse_check_text.argtypes = [ctypes.c_char_p]
lib.hlse_text_action_for_score.restype = ctypes.c_char_p
lib.hlse_text_action_for_score.argtypes = [ctypes.c_int]

lib.hlse_check_url.restype = UrlVerdict
lib.hlse_check_url.argtypes = [ctypes.c_char_p]
lib.hlse_action_for_score.restype = ctypes.c_char_p
lib.hlse_action_for_score.argtypes = [ctypes.c_int]

lib.hlse_version.restype = ctypes.c_char_p
lib.hlse_version.argtypes = []


def _decode(reasons_field, n):
    return [
        bytes(reasons_field[i]).rstrip(b"\x00").decode("utf-8", errors="replace")
        for i in range(n)
    ]


def check_text(text):
    v = lib.hlse_check_text(text.encode("utf-8"))
    return {
        "score": v.score,
        "action": lib.hlse_text_action_for_score(v.score).decode("utf-8"),
        "reasons": _decode(v.reasons, v.n_reasons),
    }


def check_url(url):
    v = lib.hlse_check_url(url.encode("utf-8"))
    return {
        "score": v.score,
        "action": lib.hlse_action_for_score(v.score).decode("utf-8"),
        "reasons": _decode(v.reasons, v.n_reasons),
    }


def version():
    return lib.hlse_version().decode("utf-8")


def main():
    print(f"=== HLSE Core (Python ctypes) v{version()} ===\n")
    fails = 0

    print("URL tests:")
    url_cases = [
        ("https://g00gle.com", 40),
        ("https://github.com", 0),
        ("https://paypal.com.attacker.xyz/verify", 50),
        ("https://en.wikipedia.org/wiki/Verify", 0),
    ]
    for url, min_score in url_cases:
        r = check_url(url)
        ok = (r["score"] >= min_score) if min_score > 0 else (r["score"] < 40)
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] {r['action']:7s} [{r['score']:3d}]  {url}")
        if not ok:
            fails += 1
    print()

    print("Text tests:")
    text_cases = [
        ("URGENT: wire $50,000 immediately to this account", 40),
        ("Meeting at 3pm tomorrow", 0),
        ("Microsoft Support: your PC has a virus, call us now", 40),
        ("Hi sweetie, send Bitcoin and I'll 3x your money", 40),
        ("\u81f3\u6025\uff01\u30a2\u30de\u30be\u30f3\u30ae\u30d5\u30c8\u30ab\u30fc\u30c9", 30),
        ("\u660e\u65e5\u306e\u30df\u30fc\u30c6\u30a3\u30f3\u30b0\u300115\u6642\u306b\u5909\u66f4", 0),
    ]
    for text, min_score in text_cases:
        r = check_text(text)
        ok = (r["score"] >= min_score) if min_score > 0 else (r["score"] == 0)
        marker = "OK  " if ok else "FAIL"
        preview = text[:55] if all(ord(c) < 128 for c in text) else text[:25]
        print(f"  [{marker}] {r['action']:7s} [{r['score']:3d}]  {preview}")
        if not ok:
            fails += 1
    print()

    total = len(url_cases) + len(text_cases)
    print(f"Result: {total - fails}/{total} passed")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
