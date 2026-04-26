#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashmap.py — A smart hash type identifier and hashcat helper
Version: 7.1 (Smart Scoring Engine v2 - Fixed)
Author: Xzar
Description:
  - Implements Smart Scoring Engine v2 with advanced detection:
    * Layer 1: High-priority prefix matching for MCF/LDAP hashes (+500 bonus)
    * Layer 2: Base64 binary analysis for LDAP hash byte-length detection
    * Layer 3: Shannon entropy calculation for false positive filtering
    * Layer 4: Strict length/charset enforcement (no tolerance for short hashes)
  - Signature database with over 150 hash types loaded from an external JSON file.
  - Dynamic path resolution makes the script portable and easy to install system-wide.
Usage:
  hashmap <hash>
  hashmap -f <hash_file> --tolerance 10
"""
from __future__ import annotations
import re
import sys
import json
import argparse
import base64
import os
import math
from typing import List, Tuple, Dict, Any, Optional, Set, NamedTuple
from collections import Counter

# ---- rich detection & utilities (fallback if not installed) ----
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

    class _FakeConsole:
        def print(self, *args, **kwargs):
            text = " ".join(map(str, args))
            text = re.sub(r"\[bold red\](.*?)\[/bold red\]", r"ERROR: \1", text)
            text = re.sub(r"\[bold green\](.*?)\[/bold green\]", r"SUCCESS: \1", text)
            text = re.sub(r"\[yellow\](.*?)\[/yellow\]", r"WARNING: \1", text)
            text = re.sub(r"\[.*?\]", "", text)
            sys.stdout.write(text + "\n")

        def rule(self, *args, **kwargs):
            print("=" * 80)

    console = _FakeConsole()

# ------------------------ CONFIG / CONSTANTS ------------------------
PATTERN_MATCH_MULTIPLIER: float = 2.0
CHARSET_MATCH_MULTIPLIER: float = 0.6
MAX_CANDIDATES_DEFAULT: int = 10
LAST_UPDATE_FILE: str = ".hashmap_last_update"
SIGNATURES_URL: Optional[str] = None

# Scoring Engine v2 Constants
PREFIX_MATCH_BONUS: float = 500.0  # Layer 1: Massive bonus for prefix match
BASE64_BYTE_MATCH_BONUS: float = 100.0  # Layer 2: Bonus for decoded byte length match
ENTROPY_PENALTY_MULTIPLIER: float = 50.0  # Layer 3: Heavy penalty for low entropy
SHORT_HASH_LENGTH_THRESHOLD: int = (
    40  # Layer 4: No tolerance for hashes shorter than this
)

# --- Dynamic path resolution for the signatures file ---
try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    SIGNATURES_FILE = os.path.join(SCRIPT_DIR, "hashmap_signatures.json")
except NameError:
    SIGNATURES_FILE = "hashmap_signatures.json"


# ============================================================================
# LAYER 1: KNOWN_PREFIXES - Hardcoded prefix-to-algorithm mapping
# If hash_str.startswith(prefix), this algorithm gets +500 bonus and others
# are filtered out. This fixes MCF hash detection failures.
# ============================================================================
class PrefixMatch(NamedTuple):
    """Represents a known hash prefix with its algorithm info."""

    name: str
    hashcat_mode: Optional[int]
    notes: str


KNOWN_PREFIXES: Dict[str, PrefixMatch] = {
    # MD5-Crypt (Unix)
    "$1$": PrefixMatch(
        "md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)", 500, "MD5-based Unix crypt"
    ),
    # Bcrypt variants
    "$2$": PrefixMatch("bcrypt $2*$, Blowfish (Unix)", 3200, "Bcrypt"),
    "$2a$": PrefixMatch("bcrypt $2*$, Blowfish (Unix)", 3200, "Bcrypt"),
    "$2b$": PrefixMatch("bcrypt $2*$, Blowfish (Unix)", 3200, "Bcrypt"),
    "$2y$": PrefixMatch("bcrypt $2*$, Blowfish (Unix)", 3200, "Bcrypt"),
    # SHA256-Crypt (Unix)
    "$5$": PrefixMatch(
        "sha256crypt $5$, SHA256 (Unix)", 7400, "SHA256-based Unix crypt"
    ),
    # SHA512-Crypt (Unix)
    "$6$": PrefixMatch(
        "sha512crypt $6$, SHA512 (Unix)", 1800, "SHA512-based Unix crypt"
    ),
    # Argon2
    "$argon2i$": PrefixMatch("Argon2i", 13100, "Argon2i"),
    "$argon2d$": PrefixMatch("Argon2d", 13100, "Argon2d"),
    "$argon2id$": PrefixMatch("Argon2id", 13100, "Argon2id"),
    "$argon2": PrefixMatch("Argon2", 13100, "Argon2 variant"),
    # LDAP hashes
    "{SSHA}": PrefixMatch("LDAP {SSHA}", 111, "LDAP Salted SHA1"),
    "{SHA}": PrefixMatch("LDAP {SHA}", 101, "LDAP SHA1"),
    "{SSHA256}": PrefixMatch("LDAP {SSHA256}", 1711, "LDAP Salted SHA256"),
    "{SSHA512}": PrefixMatch("LDAP {SSHA512}", 1711, "LDAP Salted SHA512"),
    "{SMD5}": PrefixMatch("LDAP {SMD5}", 6300, "LDAP Salted MD5"),
    "{MD5}": PrefixMatch("LDAP {MD5}", 6300, "LDAP MD5"),
    # PHPass
    "$P$": PrefixMatch("phpass (WordPress, Joomla)", 400, "PHPass portable hash"),
    "$H$": PrefixMatch("phpass (phpBB3)", 400, "PHPass portable hash"),
    # Apache
    "$apr1$": PrefixMatch("Apache $apr1$ MD5", 1600, "Apache MD5"),
    # Scrypt
    "$7$": PrefixMatch("scrypt", 8900, "scrypt"),
    "$scrypt$": PrefixMatch("scrypt", 8900, "scrypt"),
    # Yescrypt
    "$y$": PrefixMatch("yescrypt", 13400, "yescrypt"),
    # PBKDF2
    "$pbkdf2-sha256$": PrefixMatch("PBKDF2-HMAC-SHA256", 10900, "PBKDF2-SHA256"),
    "$pbkdf2-sha512$": PrefixMatch("PBKDF2-HMAC-SHA512", 12100, "PBKDF2-SHA512"),
    "$pbkdf2$": PrefixMatch("PBKDF2-HMAC-SHA1", 12000, "PBKDF2-SHA1"),
    # Bazy danych
    "*": PrefixMatch("MySQL 4.1/MySQL 5", 300, "MySQL 4.1+"),
    "md5": PrefixMatch("PostgreSQL MD5", 11400, "PostgreSQL md5(pass+user)"),
}


# ============================================================================
# LAYER 2: Base64 decoded byte lengths for LDAP-style hashes
# ============================================================================
DECODED_BYTE_SIGNATURES: Dict[int, List[Tuple[str, Optional[int], str]]] = {
    20: [  # SHA1 = 20 bytes
        ("SHA1 (Base64)", 100, "SHA1 hash in Base64"),
        ("LDAP {SHA}", 101, "LDAP SHA1"),
    ],
    # SSHA = 20 bytes SHA1 + variable salt (typically 4-16 bytes)
    # So 24-36 byte range indicates SSHA
    32: [  # SHA256 = 32 bytes
        ("SHA256 (Base64)", 1400, "SHA256 hash in Base64"),
    ],
    64: [  # SHA512 = 64 bytes
        ("SHA512 (Base64)", 1700, "SHA512 hash in Base64"),
    ],
    16: [  # MD5 = 16 bytes
        ("MD5 (Base64)", 0, "MD5 hash in Base64"),
    ],
}

# SSHA has SHA1 (20 bytes) + salt (usually 4-16 bytes)
SSHA_BYTE_RANGE: Tuple[int, int] = (24, 40)  # 20 + 4 to 20 + 20


# ============================================================================
# LAYER 3: Shannon Entropy thresholds
# Random hex string: ~4.0 bits/char, Random base64: ~6.0 bits/char
# Low entropy strings (like "6f95959841804c00") should not match Argon2
# ============================================================================
MIN_ENTROPY_FOR_COMPLEX_HASH: float = 3.0  # Minimum entropy for Argon2/bcrypt/scrypt
ENTROPY_EXPECTED_HEX: float = 3.8
ENTROPY_EXPECTED_BASE64: float = 5.5


# ============================================================================
# LAYER 4: Charset definitions for strict validation
# ============================================================================
CHARSET_CHECKS: Dict[str, Any] = {
    "hex": lambda s: bool(re.fullmatch(r"[0-9a-fA-F]+", s)),
    "hex_upper": lambda s: bool(re.fullmatch(r"[0-9A-F]+", s)),
    "radix64": lambda s: bool(re.fullmatch(r"[A-Za-z0-9./$*=\-_\+]+", s)),
    "base64": lambda s: is_base64(s),
    "bcrypt": lambda s: bool(re.fullmatch(r"[./A-Za-z0-9]+", s)),
    "ascii": lambda s: all(32 <= ord(ch) <= 126 for ch in s),
}

# Characters that CANNOT appear in hex strings
HEX_INVALID_CHARS: set = set(
    "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
)


# ---------------- Helper Functions ----------------
def is_base64(s: str) -> bool:
    """Check if string is valid base64 format."""
    if not isinstance(s, str) or not s or not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return False
    return len(s) % 4 == 0


def is_valid_base64_not_hex(s: str) -> bool:
    """Check if string is Base64 but NOT pure hex (contains g-z or +/)."""
    if not is_base64(s):
        return False
    # If it only contains hex chars, it's not "base64-specific"
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        return False
    return True


def percent(x: float) -> float:
    """Convert decimal to percentage."""
    return round(x * 100, 2)


def is_valid_hash_line(line: str) -> bool:
    """Filter out invalid hash lines from input."""
    s = line.strip()
    if len(s) < 8:  # Allow shorter hashes like CRC32
        return False
    if any(word in s.lower() for word in ["hashes", "analysis", "hash:", "(cd", "---"]):
        return False
    if s.count(" ") > 2:
        return False
    # Allow parentheses for some hash formats but filter obvious non-hashes
    if "(" in s and ")" in s and not s.startswith("{"):
        return False
    return True


def get_similar_candidates(
    candidates: List[Dict], tolerance_pct: float = 15.0
) -> List[Dict]:
    """Return candidates within tolerance percentage of best score."""
    if not candidates:
        return []
    best_score = candidates[0]["score"]
    if best_score == 0:
        return [c for c in candidates if c["score"] == 0]
    threshold = best_score * (1 - tolerance_pct / 100)
    return [c for c in candidates if c["score"] >= threshold]


def split_hash_salt(line: str) -> Tuple[str, str]:
    """Split input into hash and salt components (only for simple hash:salt format)."""
    # Don't split MCF format hashes that use $ or { delimiters
    if line.strip().startswith("$") or line.strip().startswith("{"):
        return line.strip(), ""
    parts = line.strip().split(":")
    if len(parts) == 2:
        hash_part, salt_part = parts
        if len(hash_part) > len(salt_part) and len(salt_part) > 0:
            return hash_part, salt_part
    return line.strip(), ""


def calculate_shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string (bits per character).
    High entropy indicates randomness typical of cryptographic hashes.
    Low entropy (< 3.0) suggests simple patterns or non-random data.
    """
    if not s:
        return 0.0
    length = len(s)
    freq = Counter(s)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


def try_base64_decode(s: str) -> Optional[bytes]:
    """
    Attempt to decode a Base64 string to raw bytes.
    Returns None if not valid Base64 or decode fails.
    """
    # Strip any prefix like {SHA} or {SSHA}
    data = s
    if s.startswith("{") and "}" in s:
        end_idx = s.index("}") + 1
        detected_prefix = s[:end_idx].upper()
        data = s[end_idx:]

    if not data or len(data) % 4 != 0:
        return None

    # Check if it looks like base64
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", data):
        return None

    try:
        decoded = base64.b64decode(data)
        if len(decoded) > 0:
            return decoded
    except Exception:
        pass
    return None


def is_hex_string(s: str) -> bool:
    """Check if string contains only valid hex characters."""
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def has_hex_invalid_chars(s: str) -> bool:
    """Check if string contains characters invalid for hex (like G, Z, etc.)."""
    return bool(set(s) & HEX_INVALID_CHARS)


# ============================================================================
# LAYER 1: Check for known prefix match (highest priority)
# ============================================================================
def check_known_prefix(hash_str: str) -> Optional[Dict[str, Any]]:
    """
    Check if hash starts with a known prefix.
    Returns a high-scoring result dict if matched, None otherwise.
    This OVERRIDES all other detection logic.
    """
    s = hash_str.strip()

    # Sort prefixes by length (longest first) to match most specific
    sorted_prefixes = sorted(KNOWN_PREFIXES.keys(), key=len, reverse=True)

    for prefix in sorted_prefixes:
        # Case-insensitive for LDAP-style, case-sensitive for $-style
        if prefix.startswith("{"):
            if s.upper().startswith(prefix.upper()):
                match = KNOWN_PREFIXES[prefix]
                return {
                    "name": match.name,
                    "score": PREFIX_MATCH_BONUS,
                    "probability_pct": 95.24,
                    "details": [f"Prefix '{prefix}' match: +{PREFIX_MATCH_BONUS}"],
                    "notes": match.notes,
                    "hashcat_mode": match.hashcat_mode,
                }
        else:
            if s.startswith(prefix):
                match = KNOWN_PREFIXES[prefix]
                return {
                    "name": match.name,
                    "score": PREFIX_MATCH_BONUS,
                    "probability_pct": 95.24,
                    "details": [f"Prefix '{prefix}' match: +{PREFIX_MATCH_BONUS}"],
                    "notes": match.notes,
                    "hashcat_mode": match.hashcat_mode,
                }

    return None


# ============================================================================
# LAYER 2: Base64 binary analysis for LDAP-style hashes
# ============================================================================
def analyze_base64_content(hash_str: str) -> Optional[Dict[str, Any]]:
    """
    If hash appears to be Base64 (not hex), decode and analyze byte length.
    Returns detection result if confident, None otherwise.
    """
    s = hash_str.strip()

    # Check if it's LDAP-style with prefix
    prefix_stripped = s
    detected_prefix = None
    if s.startswith("{") and "}" in s:
        end_idx = s.index("}") + 1
        detected_prefix = s[:end_idx].upper()
        prefix_stripped = s[end_idx:]

    # Only process if it looks like Base64 and NOT pure hex
    if not is_valid_base64_not_hex(prefix_stripped):
        return None

    decoded = try_base64_decode(s)
    if decoded is None:
        return None

    byte_len = len(decoded)
    details = [f"Base64 decoded to {byte_len} bytes"]

    # Check for SSHA (SHA1 + salt = 24-40 bytes typically)
    if detected_prefix == "{SSHA}" or (
        SSHA_BYTE_RANGE[0] <= byte_len <= SSHA_BYTE_RANGE[1]
    ):
        if detected_prefix == "{SSHA}":
            return {
                "name": "LDAP {SSHA}",
                "score": PREFIX_MATCH_BONUS + BASE64_BYTE_MATCH_BONUS,
                "probability_pct": 95.24,
                "details": details + ["SSHA: SHA1 (20 bytes) + salt"],
                "notes": "LDAP Salted SHA1",
                "hashcat_mode": 111,
            }

    # Check exact byte lengths
    if byte_len in DECODED_BYTE_SIGNATURES:
        sigs = DECODED_BYTE_SIGNATURES[byte_len]
        best = sigs[0]
        return {
            "name": best[0],
            "score": BASE64_BYTE_MATCH_BONUS,
            "probability_pct": 80.0,
            "details": details + [f"Matches {best[0]} byte length"],
            "notes": best[2],
            "hashcat_mode": best[1],
        }

    return None


# ============================================================================
# SCORING ENGINE v2 - Main scoring logic
# ============================================================================
class ScoringEngine:
    """
    Smart Scoring Engine v2 - Implements 4-layer detection:
    Layer 1: Prefix matching (handled externally)
    Layer 2: Base64 binary analysis (handled externally)
    Layer 3: Entropy-based false positive filtering
    Layer 4: Strict length/charset enforcement
    """

    def __init__(self, input_string: str):
        """Initialize engine with input hash string."""
        self.original_input: str = input_string.strip()
        self.hash_part, self.salt_part = split_hash_salt(self.original_input)
        self._entropy: float = calculate_shannon_entropy(self.hash_part)
        self._is_hex: bool = is_hex_string(self.hash_part)
        self._has_invalid_hex: bool = has_hex_invalid_chars(self.hash_part)
        self._hash_length: int = len(self.hash_part)

    def score_candidate(self, sig: Dict) -> Tuple[float, List[str], bool]:
        """
        Score a candidate signature against the input hash.
        Returns (score, details, is_disqualified).

        Implements:
        - Layer 3: Entropy filtering
        - Layer 4: Strict length/charset enforcement
        """
        score = 0.0
        details: List[str] = []
        s = self.hash_part

        # ================================================================
        # LAYER 4a: Strict Charset Enforcement
        # If signature expects "hex" and input has invalid hex chars -> score = 0
        # ================================================================
        charset = sig.get("charset", "")
        if charset in ("hex", "hex_upper"):
            if self._has_invalid_hex or not self._is_hex:
                return (
                    0.0,
                    ["Charset 'hex' violation: contains invalid characters"],
                    True,
                )

        # ================================================================
        # LAYER 4b: Strict Length Enforcement for short hashes
        # No tolerance (+/-2) for hashes under 40 characters
        # ================================================================
        sig_lengths = sig.get("lengths", [])
        if sig_lengths:
            exact_match = self._hash_length in sig_lengths

            if self._hash_length < SHORT_HASH_LENGTH_THRESHOLD:
                # STRICT mode: exact length match required for short hashes
                if not exact_match:
                    return (
                        0.0,
                        [f"Length {self._hash_length} != required {sig_lengths}"],
                        True,
                    )
                else:
                    bonus = sig.get("weight", 100)
                    score += bonus
                    details.append(
                        f"Length exact match ({self._hash_length}): +{bonus}"
                    )
            else:
                # For longer hashes, allow small tolerance
                if exact_match:
                    bonus = sig.get("weight", 100)
                    score += bonus
                    details.append(f"Length ({self._hash_length}): +{bonus}")
                else:
                    # Check tolerance for longer hashes only
                    for L in sig_lengths:
                        if abs(self._hash_length - L) <= 2:
                            bonus = sig.get("weight", 100) * 0.12
                            score += bonus
                            details.append(f"Near length (~{L}): +{bonus:.1f}")
                            break
                    else:
                        # No length match at all
                        return (
                            0.0,
                            [f"Length {self._hash_length} not in {sig_lengths}"],
                            True,
                        )

        # ================================================================
        # LAYER 3: Entropy-based false positive filtering
        # Penalize low-entropy strings matching high-entropy signatures
        # ================================================================
        sig_name_lower = sig.get("name", "").lower()
        is_complex_hash = any(
            x in sig_name_lower
            for x in ["argon2", "bcrypt", "scrypt", "pbkdf2", "yescrypt"]
        )

        if is_complex_hash:
            if self._entropy < MIN_ENTROPY_FOR_COMPLEX_HASH:
                penalty = ENTROPY_PENALTY_MULTIPLIER * (
                    MIN_ENTROPY_FOR_COMPLEX_HASH - self._entropy
                )
                score -= penalty
                details.append(
                    f"Low entropy ({self._entropy:.2f}) for complex hash: -{penalty:.1f}"
                )
                # If score goes very negative, disqualify
                if score < -100:
                    return 0.0, details + ["DISQUALIFIED: entropy too low"], True

        # General entropy check for hex hashes
        if charset == "hex" and self._entropy < ENTROPY_EXPECTED_HEX * 0.7:
            penalty = 20.0 * (1 - self._entropy / ENTROPY_EXPECTED_HEX)
            score -= penalty
            details.append(f"Low entropy for hex ({self._entropy:.2f}): -{penalty:.1f}")

        # ================================================================
        # Pattern matching bonus
        # ================================================================
        pattern = sig.get("pattern", "")
        if pattern:
            try:
                if re.fullmatch(pattern, self.original_input, re.IGNORECASE):
                    bonus = sig.get("weight", 100) * PATTERN_MATCH_MULTIPLIER
                    score += bonus
                    details.append(f"Pattern match: +{bonus:.1f}")
            except re.error:
                pass

        # ================================================================
        # Charset match bonus (if passed validation)
        # ================================================================
        if charset and charset in CHARSET_CHECKS:
            check_func = CHARSET_CHECKS[charset]
            if check_func(s):
                bonus = sig.get("weight", 100) * CHARSET_MATCH_MULTIPLIER
                score += bonus
                details.append(f"Charset '{charset}': +{bonus:.1f}")

        # ================================================================
        # Priority bonus
        # ================================================================
        priority = sig.get("priority", 50)
        priority_bonus = (priority - 50) * 0.3
        score += priority_bonus
        if abs(priority_bonus) > 0.1:
            details.append(f"Priority ({priority}): {priority_bonus:+.1f}")

        # ================================================================
        # NTLM heuristics
        # ================================================================
        heuristic_bonus = self._apply_ntlm_heuristics(sig, details)
        score += heuristic_bonus

        # ================================================================
        # Salt handling
        # ================================================================
        if self.salt_part:
            salt_pos = sig.get("salt_position", "none")
            if salt_pos != "none":
                score *= 1.2
                details.append("Salt detected: ×1.2")
            else:
                score *= 0.5
                details.append("Salt unexpected: ×0.5")

        return max(score, 0.0), details, False

    def _apply_ntlm_heuristics(self, sig: Dict, details: List[str]) -> float:
        """Apply NTLM vs MD5 heuristics based on character patterns."""
        bonus = 0.0
        s = self.hash_part.lower()
        sig_name = sig.get("name", "").lower()

        if "ntlm" in sig_name:
            if not re.search(r"(.)\1{3,}", s):
                bonus += 3
                details.append("NTLM hint: +3")
        elif "md5" in sig_name and "ntlm" not in sig_name:
            if re.search(r"(.)\1{4,}", s):
                bonus -= 4
                details.append("MD5 less likely (repetition): -4")
        return bonus

    @property
    def entropy(self) -> float:
        """Get calculated entropy of the hash."""
        return self._entropy


# ============================================================================
# MAIN DETECTION FUNCTION
# ============================================================================
def detect_hash(
    input_str: str,
    signatures: List[Dict[str, Any]],
    top_k: int = MAX_CANDIDATES_DEFAULT,
) -> List[Dict[str, Any]]:
    """
    Detect hash type using Smart Scoring Engine v2.

    Detection order:
    1. LAYER 1: Check known prefixes (MCF, LDAP) - if match, return immediately
    2. LAYER 2: Base64 binary analysis - if confident, include in results
    3. LAYER 3+4: Score against signatures with entropy/length/charset checks
    """
    s = input_str.strip()

    # ================================================================
    # LAYER 1: Known prefix check (highest priority)
    # ================================================================
    prefix_result = check_known_prefix(s)
    if prefix_result:
        # Return prefix match as the definitive answer
        return [prefix_result]

    # ================================================================
    # LAYER 2: Base64 binary analysis
    # ================================================================
    base64_result = analyze_base64_content(s)
    candidates = []
    if base64_result:
        candidates.append(base64_result)

    # ================================================================
    # LAYERS 3 & 4: Score against JSON signatures
    # ================================================================
    engine = ScoringEngine(input_str)

    # Pre-filter signatures by length (with some margin for longer hashes)
    hash_len = len(engine.hash_part)
    prefiltered_sigs = []
    for sig in signatures:
        lengths = sig.get("lengths", [])
        if lengths:
            if hash_len < SHORT_HASH_LENGTH_THRESHOLD:
                # Strict: must match exactly for short hashes
                if hash_len in lengths:
                    prefiltered_sigs.append(sig)
            else:
                # Allow tolerance for longer hashes
                if hash_len in lengths or any(abs(hash_len - L) <= 2 for L in lengths):
                    prefiltered_sigs.append(sig)
        elif sig.get("pattern"):
            prefiltered_sigs.append(sig)

    for sig in prefiltered_sigs:
        score, details, is_disqualified = engine.score_candidate(sig)

        if is_disqualified:
            continue

        if score > 0:
            candidates.append(
                {
                    "sig": sig,
                    "score": score,
                    "details": details,
                    "name": sig["name"],
                    "notes": sig.get("notes", ""),
                    "hashcat_mode": sig.get("hashcat_mode"),
                }
            )

    # Sort by score
    candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
    if not candidates:
        return []

    # Format output
    max_score = candidates[0].get("score", 1.0) if candidates else 1.0
    output = []
    for cand in candidates[:top_k]:
        prob = (
            percent(min(cand.get("score", 0) / (max_score * 1.05), 1.0))
            if max_score > 0
            else 0.0
        )
        output.append(
            {
                "name": cand.get("name", cand.get("sig", {}).get("name", "Unknown")),
                "score": round(cand.get("score", 0), 2),
                "probability_pct": prob,
                "details": cand.get("details", []),
                "notes": cand.get("notes", ""),
                "hashcat_mode": cand.get("hashcat_mode"),
            }
        )

    return output


# ------------------ Legacy Compatibility ------------------
def score_candidate(hash_str: str, sig: Dict) -> Tuple[float, List[str]]:
    """Legacy wrapper for backward compatibility."""
    engine = ScoringEngine(hash_str)
    score, details, _ = engine.score_candidate(sig)
    return score, details


def apply_ntlm_heuristics(hash_str: str, sig: Dict, details: List[str]) -> float:
    """Legacy wrapper for NTLM heuristics."""
    engine = ScoringEngine(hash_str)
    return engine._apply_ntlm_heuristics(sig, details)


# ------------------ Signature Management ------------------
def load_signatures() -> List[Dict[str, Any]]:
    """Load hash signatures from JSON file."""
    if not os.path.exists(SIGNATURES_FILE):
        console.print(
            f"[bold red]Critical Error: Signatures file "
            f"'{os.path.basename(SIGNATURES_FILE)}' not found.[/bold red]"
        )
        sys.exit(1)
    try:
        with open(SIGNATURES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        console.print(
            f"[bold red]Error: Could not load signatures file "
            f"'{os.path.basename(SIGNATURES_FILE)}' ({e}).[/bold red]"
        )
        sys.exit(1)


# ------------------ Output & Helpers ------------------
def gen_hashcat_cmd(hash_str: str, best_candidate: Dict) -> str:
    """Generate a sample hashcat command."""
    mode = best_candidate.get("hashcat_mode")
    if mode is None:
        return f"# No certain hashcat mode for {best_candidate['name']}. Please verify manually."
    return f'hashcat -m {mode} -a 0 "{hash_str}" /path/to/wordlist.txt'


HELP_MD = """
# hashmap v7.1 — Smart Hash Identifier + Hashcat Helper

**Smart Scoring Engine v2 Features:**
- Layer 1: High-priority prefix matching for MCF/LDAP (+500 bonus)
- Layer 2: Base64 binary analysis (decoded byte length detection)
- Layer 3: Shannon entropy filtering (false positive prevention)
- Layer 4: Strict length/charset enforcement (no tolerance < 40 chars)

**Usage**
- `hashmap <hash>`
- `hashmap -f <hash_file>`
- `cat hashes.txt | hashmap`

**Output Options**
- `--json`             Output in JSON format.
- `--hashcat-only`     Print only the best hashcat mode (`-m`).
- `--cmd`              Print a suggested hashcat command.
- `-k, --top`          Show top K candidates (default: 10).
- `-v, --verbose`      Show detailed scoring information.

**Filtering & Accuracy**
- `--tolerance <%>`    Show all candidates within N% of the top score (default: 15.0).
- `--strict`           Show only the single best match (overrides tolerance).
- `--min-weight <N>`   Ignore signatures with a weight lower than N.
"""


def print_help_and_exit(parser: argparse.ArgumentParser) -> None:
    """Display help message and exit."""
    if RICH_AVAILABLE:
        console.print(
            Panel(
                Markdown(HELP_MD),
                title="[bold]hashmap v7.1 — Help[/bold]",
                expand=False,
                border_style="blue",
            )
        )
    else:
        print(HELP_MD)
    sys.exit(0)


def pretty_print_results(
    hash_str: str, candidates: List[Dict[str, Any]], verbose: bool
) -> None:
    """Pretty print detection results using rich tables."""
    if not candidates:
        console.print(f"[yellow]Could not identify hash: {hash_str}[/yellow]")
        return

    if RICH_AVAILABLE:
        title = (
            f"[bold]Analysis for: [white]"
            f"{hash_str if len(hash_str) < 80 else hash_str[:77] + '...'}[/white][/bold]"
        )
        table = Table(show_header=True, header_style="bold magenta", title=title)
        table.add_column("#", style="dim", width=2)
        table.add_column("Algorithm", style="bold", min_width=20)
        table.add_column("Mode", style="cyan", width=8)
        table.add_column("Score", style="yellow", width=8)
        if verbose:
            table.add_column("Scoring Details", style="white", min_width=30)
        table.add_column("Notes", style="dim")

        for i, c in enumerate(candidates, 1):
            mode = (
                f"-m {c['hashcat_mode']}"
                if c.get("hashcat_mode") is not None
                else "N/A"
            )
            score = f"{c['score']:.1f}"
            row_items = [str(i), c["name"], mode, score]
            if verbose:
                row_items.append(", ".join(c["details"]))
            row_items.append(c["notes"])
            table.add_row(*row_items)
        console.print(table)
    else:
        print(f"\n--- Analysis for: {hash_str} ---")
        for i, c in enumerate(candidates, 1):
            mode = (
                f"-m {c['hashcat_mode']}"
                if c.get("hashcat_mode") is not None
                else "N/A"
            )
            print(f"{i}. {c['name']} (Score: {c['score']:.1f})")
            print(f"   Mode: {mode} | Notes: {c['notes']}")
        print("-" * (22 + len(hash_str)))


# ------------------ CLI Main ------------------
def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="hashmap v7.1 — Smart Hash Identifier", add_help=False
    )
    parser.add_argument("hashes", nargs="*", help="One or more hashes to identify")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument(
        "-k",
        "--top",
        type=int,
        default=MAX_CANDIDATES_DEFAULT,
        help=f"Show top K candidates (default: {MAX_CANDIDATES_DEFAULT})",
    )
    parser.add_argument(
        "--hashcat-only", action="store_true", help="Print only the best hashcat mode"
    )
    parser.add_argument(
        "--cmd", action="store_true", help="Generate a sample hashcat command"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed scoring information"
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=15.0,
        help="Show candidates within N%% of top score (def: 15%%)",
    )
    parser.add_argument(
        "--strict", action="store_true", help="Show only best match (ignores tolerance)"
    )
    parser.add_argument(
        "--min-weight", type=int, default=0, help="Ignore signatures with weight < N"
    )
    parser.add_argument(
        "-h", "--help", action="store_true", help="Show this help message"
    )
    args = parser.parse_args()

    if args.help or (len(sys.argv) == 1 and sys.stdin.isatty()):
        print_help_and_exit(parser)

    signatures = load_signatures()

    # Filter signatures by weight if specified
    if args.min_weight > 0:
        signatures = [s for s in signatures if s.get("weight", 0) >= args.min_weight]

    all_hashes = args.hashes

    # Load hashes from file
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                all_hashes.extend(
                    [line.strip() for line in f if is_valid_hash_line(line)]
                )
        except FileNotFoundError:
            console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
            sys.exit(1)
    elif not sys.stdin.isatty():
        stdin_data = sys.stdin.read()
        all_hashes.extend(
            [
                line.strip()
                for line in stdin_data.splitlines()
                if is_valid_hash_line(line)
            ]
        )

    all_hashes = [h for h in all_hashes if is_valid_hash_line(h)]

    if not all_hashes:
        console.print("[yellow]No valid hashes provided. Use -h for help.[/yellow]")
        sys.exit(0)

    results_json = {}
    for hash_str in all_hashes:
        if not hash_str:
            continue

        candidates = detect_hash(hash_str, signatures, top_k=args.top)

        if not candidates:
            if not args.json:
                console.print(f"[yellow]Could not identify hash: {hash_str}[/yellow]")
            continue

        # Apply tolerance or strict mode
        if args.strict:
            final_candidates = candidates[:1]
        else:
            final_candidates = get_similar_candidates(candidates, args.tolerance)

        if not final_candidates:
            if not args.json:
                console.print(
                    f"[yellow]No candidates for hash: {hash_str} within tolerance[/yellow]"
                )
            continue

        best_candidate = final_candidates[0]

        if args.json:
            results_json[hash_str] = final_candidates
        elif args.hashcat_only:
            print(best_candidate.get("hashcat_mode", "N/A"))
        elif args.cmd:
            print(gen_hashcat_cmd(hash_str, best_candidate))
        else:
            pretty_print_results(hash_str, final_candidates, args.verbose)

    if args.json:
        console.print(json.dumps(results_json, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
