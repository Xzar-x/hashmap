#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashmap.py — inteligentny detektor typów hashy + helper hashcat -m/--cmd
Wersja: 1.6 (pełna finalna)
Autor: Xzar
Opis:
  - kolorowy output przy użyciu rich
  - konsolidacja JSON po wszystkich hashach
  - wsparcie dla hash:salt (salt_position)
  - obsługa testów, hashcat command, hashcat only
Użycie:
  hashmap.py -h
  hashmap.py <hash>
  hashmap.py --cmd <hash>
  hashmap.py --test
"""
from __future__ import annotations
import re
import sys
import math
import json
import argparse
from collections import OrderedDict
from typing import List, Tuple, Dict, Any
import base64

# ---- rich detection & utilities (fallback if not installed) ----
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False
    class _FakeConsole:
        def print(self, *args, **kwargs):
            for a in args:
                sys.stdout.write(str(a))
            sys.stdout.write("\n")
        def rule(self, *args, **kwargs):
            print("="*80)
    console = _FakeConsole()

# ------------------------ KONFIG / STAŁE ------------------------
PATTERN_MATCH_MULTIPLIER = 2.0
PATTERN_MISS_PENALTY = 0.08
LENGTH_NEAR_MULTIPLIER = 0.12
CHARSET_MATCH_MULTIPLIER = 0.6
CHARSET_MISS_PENALTY = 0.12
HEX_ENTROPY_SCALE = 0.03
OTHER_ENTROPY_SCALE = 0.02
MAX_CANDIDATES_DEFAULT = 8

# ---------------- pomocnicze funkcje ----------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch,0)+1
    entropy = 0.0
    length = len(s)
    for v in freq.values():
        p = v/length
        entropy -= p*math.log2(p)
    return entropy

def is_base64(s: str) -> bool:
    if not isinstance(s,str) or not s:
        return False
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    try:
        pad = (-len(s)) % 4
        base64.b64decode(s + ('=' * pad), validate=False)
        return True
    except Exception:
        return False

def percent(x):
    return round(x*100,2)

# ------------------ sygnatury + mapowanie hashcat -m ------------------
HASH_SIGNATURES: List[Dict[str, Any]] = [
    {"name":"bcrypt", "pattern": r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$", "lengths":[60], "charset":"radix64",
     "weight":200, "notes":"bcrypt $2a/$2b/$2y", "hashcat_mode":3200, "salt_position":"inline"},
    {"name":"argon2id/argon2i", "pattern": r"^\$argon2(?:i|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$",
     "lengths":[], "charset":"radix64", "weight":220, "notes":"argon2 full encoding", "hashcat_mode":None, "salt_position":"inline"},
    {"name":"scrypt-kdf", "pattern": r"^\$scrypt\$.*", "lengths":[], "charset":"ascii",
     "weight":160, "notes":"scrypt encoding", "hashcat_mode":8900, "salt_position":"inline"},
    {"name":"pbkdf2", "pattern": r"^\$pbkdf2\-[a-z0-9]+\$.*", "lengths":[], "charset":"ascii",
     "weight":150, "notes":"PBKDF2 encodings", "hashcat_mode":10900, "salt_position":"inline"},
    {"name":"md5crypt", "pattern": r"^\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$", "lengths":[], "charset":"radix64",
     "weight":180, "notes":"MD5crypt (Linux $1$)", "hashcat_mode":500, "salt_position":"inline"},
    {"name":"md5", "pattern": None, "lengths":[32], "charset":"hex",
     "weight":120, "notes":"MD5 (hex 32)", "hashcat_mode":0, "salt_position":"none"},
    {"name":"ntlm", "pattern": None, "lengths":[32], "charset":"hex",
     "weight":110, "notes":"NTLM (32 hex) - Windows", "hashcat_mode":1000, "salt_position":"none"},
    {"name":"sha1", "pattern": None, "lengths":[40], "charset":"hex",
     "weight":130, "notes":"SHA-1 (hex 40)", "hashcat_mode":100, "salt_position":"none"},
    {"name":"sha256", "pattern": None, "lengths":[64], "charset":"hex",
     "weight":160, "notes":"SHA-256 (hex 64)", "hashcat_mode":1400, "salt_position":"none"},
    {"name":"phpass", "pattern": r"^\$P\$[A-Za-z0-9./]{31}$|^\$H\$[A-Za-z0-9./]{31}$", "lengths":[34], "charset":"radix64",
     "weight":140, "notes":"phpBB/Wordpress phpass ($P$/$H$)", "hashcat_mode":400, "salt_position":"inline"},
    {"name":"wpa-pmk", "pattern": None, "lengths":[64], "charset":"hex",
     "weight":145, "notes":"WPA/WPA2 PMK/handshake hex", "hashcat_mode":2500, "salt_position":"none"},
    # hash:salt examples
    {"name":"netscape_ldap_sha", "pattern": r"^[0-9a-f]{40}$", "lengths":[40], "charset":"hex",
     "weight":150, "notes":"Netscape LDAP SHA (hash:salt)", "hashcat_mode":102, "salt_position":"external"},
    {"name":"postgres_scram_sha256", "pattern": r"^[0-9a-f]{64}$", "lengths":[64], "charset":"hex",
     "weight":180, "notes":"PostgreSQL SCRAM-SHA-256 (hash:salt)", "hashcat_mode":18200, "salt_position":"external"},
]

CHARSET_CHECKS = {
    "hex": lambda s: bool(re.fullmatch(r"[0-9a-f]{%d}" % len(s), s)),
    "hex_upper": lambda s: bool(re.fullmatch(r"[0-9A-F]{%d}" % len(s), s)),
    "radix64": lambda s: bool(re.fullmatch(r"[A-Za-z0-9./\$=\-_\+]{%d,}" % max(1,len(s)), s)),
    "base64": lambda s: is_base64(s),
    "ascii": lambda s: all(32 <= ord(ch) <= 126 for ch in s),
}

# ------------------ scoring engine ------------------
def score_candidate(hash_str: str, sig: dict) -> Tuple[float, List[str], float]:
    score = 0.0
    reasons: List[str] = []
    s = hash_str.strip()
    if sig.get("pattern"):
        try:
            if re.fullmatch(sig["pattern"], s):
                score += sig["weight"]*PATTERN_MATCH_MULTIPLIER
                reasons.append("pattern match")
            else:
                score -= sig["weight"]*PATTERN_MISS_PENALTY
        except re.error:
            pass
    if sig.get("lengths"):
        if len(s) in sig["lengths"]:
            score += sig["weight"]
            reasons.append(f"length {len(s)} matches")
        else:
            for L in sig["lengths"]:
                if abs(len(s)-L)<=1:
                    score += sig["weight"]*LENGTH_NEAR_MULTIPLIER
                    reasons.append(f"length ~{L}")
                    break
    cs = sig.get("charset")
    if cs:
        check = CHARSET_CHECKS.get(cs)
        if check:
            try:
                s_check = s
                if cs=="hex":
                    s_check=s.lower()
                if check(s_check):
                    score += sig["weight"]*CHARSET_MATCH_MULTIPLIER
                    reasons.append(f"charset {cs} OK")
                else:
                    score -= sig["weight"]*CHARSET_MISS_PENALTY
            except Exception:
                pass
    ent = shannon_entropy(s)
    if sig.get("charset")=="hex":
        score += min(ent,4.0)*(sig["weight"]*HEX_ENTROPY_SCALE)
    else:
        score += min(ent,6.5)*(sig["weight"]*OTHER_ENTROPY_SCALE)
    if "$" in s and sig.get("pattern") is None:
        if sig["name"].lower() in ("pbkdf2","scrypt-kdf","argon2id/argon2i","md5crypt","phpass"):
            score += 10
    # external salt bonus
    if sig.get("salt_position")=="external":
        if ":" in s:
            score += 10
            reasons.append("possible external salt")
    return max(score,0.0), reasons, ent

# ------------------ detection ------------------
def detect_hash(hash_str: str, top_k: int = MAX_CANDIDATES_DEFAULT) -> List[Dict[str,Any]]:
    s = hash_str.strip()
    candidates = []
    starts_with_dollar = s.startswith('$')
    if starts_with_dollar:
        matched_prefixed=[]
        for sig in HASH_SIGNATURES:
            if sig.get("pattern"):
                try:
                    if re.fullmatch(sig["pattern"], s):
                        sc, reasons, ent = score_candidate(s,sig)
                        sc += sig.get("weight",0)*0.4
                        matched_prefixed.append((sig, sc, reasons, ent))
                except re.error:
                    pass
        if matched_prefixed:
            candidates=[]
            for sig,sc,reasons,ent in matched_prefixed:
                candidates.append({
                    "name": sig["name"],
                    "score": round(sc,3),
                    "weight_base": sig.get("weight",0),
                    "length": len(s),
                    "reasons": reasons,
                    "entropy": round(ent,4),
                    "notes": sig.get("notes",""),
                    "hashcat_mode": sig.get("hashcat_mode")
                })
            candidates.sort(key=lambda x: x["score"], reverse=True)
            max_score = max(c["score"] for c in candidates) or 1.0
            for c in candidates:
                c["probability_pct"]=percent(c["score"]/max_score)
            return candidates[:top_k]
    # fallback: wszystkie sygnatury
    for sig in HASH_SIGNATURES:
        sc,reasons,ent = score_candidate(s,sig)
        candidates.append({
            "name": sig["name"],
            "score": round(sc,3),
            "weight_base": sig.get("weight",0),
            "length": len(s),
            "reasons": reasons,
            "entropy": round(ent,4),
            "notes": sig.get("notes",""),
            "hashcat_mode": sig.get("hashcat_mode")
        })
    candidates.sort(key=lambda x:x["score"], reverse=True)
    max_score = max(c["score"] for c in candidates) or 1.0
    for c in candidates:
        c["probability_pct"]=percent(c["score"]/max_score)
    return candidates[:top_k]

# ---------------- helpery dla --cmd ----------------
def detect_salt(hash_str: str) -> Tuple[str,str]:
    if ':' in hash_str and not hash_str.startswith('$'):
        parts = hash_str.split(':',1)
        return parts[0], parts[1]
    return hash_str,''

def gen_hashcat_cmd(hash_str: str, best_candidate: dict, hashfile_path='hashes.txt', wordlist='dict.txt', outfile='cracked.txt') -> str:
    mode = best_candidate.get('hashcat_mode')
    if mode is None:
        return f"# brak pewnego -m dla {best_candidate['name']}. Najlepszy kandydat: {best_candidate['name']} (prob {best_candidate['probability_pct']}%)."
    h,salt = detect_salt(hash_str)
    hashfile_content = f"{h}:{salt}" if salt else h
    cmd = f"echo '{hashfile_content}' > {hashfile_path} && hashcat -m {mode} -a 0 {hashfile_path} {wordlist} -o {outfile}"
    return cmd

# ------------------ pretty output (rich) & help ------------------
HELP_MD = """
# hashmap — smart hash identifier + hashcat helper

**Usage**
- `hashmap <hash>`
- `hashmap -f <file>`
- `hashmap --json`
- `hashmap --hashcat-only`
- `hashmap --cmd`
- `hashmap --test`

**Options**
- `-f, --file`  File with one hash per line
- `--json`      Output consolidated JSON
- `-k, --top`   Show top K candidates
- `--hashcat-only`  Print only best hashcat -m suggestion
- `--cmd`       Print suggested hashcat command for top candidate
- `--test`      Run built-in test vectors
"""

def print_help_and_exit(parser: argparse.ArgumentParser):
    if RICH_AVAILABLE:
        console.print(Panel(Markdown(HELP_MD), title="hashmap — help", expand=False))
    else:
        print(parser.format_help())
    sys.exit(0)

def pretty_print_results(hash_str: str, candidates: List[Dict[str, Any]]):
    if RICH_AVAILABLE:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=3)
        table.add_column("ALG", style="bold")
        table.add_column("mode", style="cyan", width=7)
        table.add_column("prob", style="green", width=8)
        table.add_column("score", style="yellow", width=8)
        table.add_column("reasons", style="white")
        table.add_column("notes", style="dim")
        for i,c in enumerate(candidates,1):
            mode_display=f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "(-m ?)"
            prob=f"{c['probability_pct']}%"
            reasons=', '.join(c['reasons']) if c['reasons'] else '-'
            table.add_row(str(i),c['name'],mode_display,prob,str(c['score']),reasons,c['notes'])
        console.rule(f"[bold blue]Hash: [white]{hash_str}")
        console.print(table)
        console.rule()
    else:
        print("="*100)
        print("Hash:", hash_str)
        print("-"*100)
        for i,c in enumerate(candidates,1):
            mode_display=f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "(-m unknown)"
            reasons_display=', '.join(c['reasons']) if c['reasons'] else '-'
            print(f"{i:2}. {c['name']:20} | {mode_display:9} | prob: {c['probability_pct']:6}% | score: {c['score']:7} | reasons: {reasons_display} | notes: {c['notes']}")
        print("="*100)

# ------------------ tests ------------------
def run_tests():
    """
    Wbudowane testy hashmap.
    Przykładowe hashe testowe, które sprawdzają detekcję najpopularniejszych algorytmów.
    """
    test_hashes = [
        "$2y$12$eImiTXuWVxfM37uY4JANjQ",     # bcrypt
        "$1$salt$abcd1234abcd1234abcd12",  # md5crypt
        "5f4dcc3b5aa765d61d8327deb882cf99",  # md5
        "8843d7f92416211de9ebb963ff4ce28125932878",  # sha1
        "ef797c8118f02dfb649607dd5d5d7a48", # ntlm
        "$P$B5H5j8H5K7k1G3j4h5G6I7J8K9L0M1", # phpass
    ]
    for h in test_hashes:
        candidates = detect_hash(h)
        pretty_print_results(h, candidates)

# ------------------ CLI ------------------
def main():
    parser = argparse.ArgumentParser(description="hashmap — intelligent hash identifier")
    parser.add_argument("hashes", nargs="*", help="hashes to detect")
    parser.add_argument("-f","--file", help="file with hashes")
    parser.add_argument("--json", action="store_true", help="consolidated JSON output")
    parser.add_argument("-k","--top", type=int, default=MAX_CANDIDATES_DEFAULT, help="top K candidates")
    parser.add_argument("--hashcat-only", action="store_true", help="print only best hashcat -m")
    parser.add_argument("--cmd", action="store_true", help="generate hashcat command for top candidate")
    parser.add_argument("--test", action="store_true", help="run built-in test vectors")
    parser.add_argument("--help-rich", action="store_true", help="rich formatted help")
    args = parser.parse_args()
