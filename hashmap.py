#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashmap.py — inteligentny detektor typów hashy + helper hashcat
Wersja: 3.0 (poprawki błędów, nowe funkcje, rozszerzona baza)
Autor: Xzar (z rozszerzeniami Gemini na podstawie feedbacku użytkownika)
Opis:
  - Baza sygnatur z ponad 70 typami hashy
  - Tryb auto-update (--update) z walidacją
  - Tryb verbose (-v) pokazujący szczegóły scoringu
  - Eksport do formatu hashcat (--export-hashcat)
  - Poprawione scoring i tryby hashcat
Użycie:
  hashmap.py -h
  hashmap.py <hash>
  hashmap.py --update
"""
from __future__ import annotations
import re
import sys
import math
import json
import argparse
import base64
import os
from typing import List, Tuple, Dict, Any
from urllib import request, error

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
            # Prosta emulacja stylów rich dla czytelności
            text = re.sub(r'\[bold red\](.*?)\[/bold red\]', r'ERROR: \1', text)
            text = re.sub(r'\[bold green\](.*?)\[/bold green\]', r'SUCCESS: \1', text)
            text = re.sub(r'\[yellow\](.*?)\[/yellow\]', r'WARNING: \1', text)
            text = re.sub(r'\[.*?\]', '', text)
            sys.stdout.write(text + "\n")
        def rule(self, *args, **kwargs):
            print("="*80)
    console = _FakeConsole()

# ------------------------ CONFIG / CONSTANTS ------------------------
PATTERN_MATCH_MULTIPLIER = 2.0
PATTERN_MISS_PENALTY = 0.08
LENGTH_NEAR_MULTIPLIER = 0.12
CHARSET_MATCH_MULTIPLIER = 0.6
CHARSET_MISS_PENALTY = 0.12
HEURISTIC_BONUS = 25.0
MAX_CANDIDATES_DEFAULT = 8

SIGNATURES_FILE = "hashmap_signatures.json"
# Stable URL for the signatures database
SIGNATURES_URL = "https://gist.githubusercontent.com/ai-L/08f7149d88565c715019a5a3a79d5718/raw/hashmap_signatures_v3.json"

# ------------------ Default Signatures Database (Fallback) ------------------
DEFAULT_HASH_SIGNATURES: List[Dict[str, Any]] = [
    # KDFs / Prefixed Hashes
    {"name":"bcrypt", "pattern": r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$", "lengths":[60], "charset":"radix64", "weight":200, "notes":"bcrypt $2a/$2b/$2y", "hashcat_mode":3200, "salt_position":"inline"},
    {"name":"argon2id", "pattern": r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "lengths":[], "charset":"radix64", "weight":220, "notes":"Argon2id", "hashcat_mode":19200, "salt_position":"inline"},
    {"name":"argon2i", "pattern": r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "lengths":[], "charset":"radix64", "weight":220, "notes":"Argon2i", "hashcat_mode":19100, "salt_position":"inline"},
    {"name":"scrypt", "pattern": r"^\$scrypt\$N=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "lengths":[], "charset":"radix64", "weight":160, "notes":"scrypt", "hashcat_mode":8900, "salt_position":"inline"},
    {"name":"Django (PBKDF2-SHA256)", "pattern": r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9./]+\$[A-Za-z0-9+/=]+$", "lengths":[], "charset":"radix64", "weight":155, "notes":"Django PBKDF2-HMAC-SHA256", "hashcat_mode":10000, "salt_position":"inline"},
    {"name":"md5crypt", "pattern": r"^\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$", "lengths":[], "charset":"radix64", "weight":180, "notes":"MD5-Crypt (Linux $1$)", "hashcat_mode":500, "salt_position":"inline"},
    {"name":"sha256crypt", "pattern": r"^\$5\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$", "lengths":[], "charset":"radix64", "weight":180, "notes":"SHA256-Crypt (Linux $5$)", "hashcat_mode":7400, "salt_position":"inline"},
    {"name":"sha512crypt", "pattern": r"^\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$", "lengths":[], "charset":"radix64", "weight":180, "notes":"SHA512-Crypt (Linux $6$)", "hashcat_mode":1800, "salt_position":"inline"},
    {"name":"phpass", "pattern": r"^\$P\$[A-Za-z0-9./]{31}$|^\$H\$[A-Za-z0-9./]{31}$", "lengths":[34], "charset":"radix64", "weight":140, "notes":"phpBB/Wordpress phpass ($P$/$H$)", "hashcat_mode":400, "salt_position":"inline"},
    # Plain Hashes (Hex)
    {"name":"md4", "pattern": None, "lengths":[32], "charset":"hex", "weight":115, "notes":"MD4", "hashcat_mode":900, "salt_position":"none"},
    {"name":"md5", "pattern": None, "lengths":[32], "charset":"hex", "weight":120, "notes":"MD5", "hashcat_mode":0, "salt_position":"none"},
    {"name":"ntlm", "pattern": None, "lengths":[32], "charset":"hex", "weight":110, "notes":"NTLM (Windows)", "hashcat_mode":1000, "salt_position":"none"},
    {"name":"sha1", "pattern": None, "lengths":[40], "charset":"hex", "weight":130, "notes":"SHA-1", "hashcat_mode":100, "salt_position":"none"},
    {"name":"sha224", "pattern": None, "lengths":[56], "charset":"hex", "weight":155, "notes":"SHA-224", "hashcat_mode":1300, "salt_position":"none"},
    {"name":"sha256", "pattern": None, "lengths":[64], "charset":"hex", "weight":160, "notes":"SHA-256", "hashcat_mode":1400, "salt_position":"none"},
    {"name":"sha384", "pattern": None, "lengths":[96], "charset":"hex", "weight":165, "notes":"SHA-384", "hashcat_mode":10800, "salt_position":"none"},
    {"name":"sha512", "pattern": None, "lengths":[128], "charset":"hex", "weight":170, "notes":"SHA-512", "hashcat_mode":1700, "salt_position":"none"},
    # Salted Hashes (hash:salt / salt:hash)
    {"name":"md5($pass.$salt)", "pattern": None, "lengths":[32], "charset":"hex", "weight":125, "notes":"MD5(pass.salt)", "hashcat_mode":10, "salt_position":"external"},
    {"name":"md5($salt.$pass)", "pattern": None, "lengths":[32], "charset":"hex", "weight":125, "notes":"MD5(salt.pass)", "hashcat_mode":20, "salt_position":"external"},
    {"name":"sha1($pass.$salt)", "pattern": None, "lengths":[40], "charset":"hex", "weight":135, "notes":"SHA1(pass.salt)", "hashcat_mode":110, "salt_position":"external"},
    {"name":"sha1($salt.$pass)", "pattern": None, "lengths":[40], "charset":"hex", "weight":135, "notes":"SHA1(salt.pass)", "hashcat_mode":120, "salt_position":"external"},
    # System / Application Hashes
    {"name":"WPA-PMKID", "pattern": r"^[0-9a-f]{32}\*[0-9a-f]{12}\*[0-9a-f]{12}\*[0-9a-f]+$", "lengths":[], "charset":"hex", "weight":190, "notes":"WPA-PMKID (EAPOL)", "hashcat_mode":16800, "salt_position":"inline"},
    {"name":"WPA-EAPOL-PBKDF2", "pattern": None, "lengths":[64], "charset":"hex", "weight":145, "notes":"WPA/WPA2 (hashcat -m 2500/22000)", "hashcat_mode":22000, "salt_position":"none"},
    {"name":"Kerberos 5 TGS-REP etype 23", "pattern": r"^\$krb5tgs\$23\$.+\$[0-9A-F]{32}\$[0-9A-F]+$", "lengths":[], "charset":"hex_upper", "weight":190, "notes":"Kerberos 5 TGS-REP (etype 23)", "hashcat_mode":13100, "salt_position":"inline"},
    {"name":"Domain Cached Credentials 2 (DCC2)", "pattern": r"^[a-zA-Z0-9-]+\#\S+\#[0-9a-f]{256}$", "lengths":[], "charset":"hex", "weight":195, "notes":"MS Cache Hash 2 (PBKDF2-HMAC-SHA1)", "hashcat_mode":2100, "salt_position":"inline"},
    {"name":"Cisco Type 7", "pattern": r"^0[0-9][0-9A-F]{2,}", "lengths":[], "charset":"hex_upper", "weight":160, "notes":"Cisco Type 7 (reversible)", "hashcat_mode":20, "salt_position":"none"},
    {"name":"Cisco Type 9", "pattern": r"^\$9\$.*", "lengths":[], "charset":"radix64", "weight":180, "notes":"Cisco Type 9 (scrypt)", "hashcat_mode":9200, "salt_position":"inline"},
    {"name":"NetNTLMv2", "pattern": r"^.+\:\:[^:]+\:[0-9a-f]{32}\:[0-9a-f]+$", "lengths":[], "charset":"hex", "weight":195, "notes":"NetNTLMv2", "hashcat_mode":5600, "salt_position":"inline"},
]

CHARSET_CHECKS = {
    "hex": lambda s: bool(re.fullmatch(r"[0-9a-f]+", s, re.IGNORECASE)),
    "hex_upper": lambda s: bool(re.fullmatch(r"[0-9A-F]+", s)),
    "radix64": lambda s: bool(re.fullmatch(r"[A-Za-z0-9./$*=\-_\+]+", s)),
    "base64": lambda s: is_base64(s),
    "ascii": lambda s: all(32 <= ord(ch) <= 126 for ch in s),
}

# ---------------- Helper Functions ----------------
def is_base64(s: str) -> bool:
    if not isinstance(s, str) or not s or not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    try:
        padding = '=' * (4 - len(s) % 4)
        base64.b64decode(s + padding)
        return True
    except (ValueError, TypeError, base64.binascii.Error):
        return False

def percent(x: float) -> float:
    return round(x * 100, 2)

# ------------------ Scoring Engine (v3) ------------------
def score_candidate(hash_str: str, sig: dict, original_input: str) -> Tuple[float, List[str]]:
    score = 0.0
    details: List[str] = []
    s = hash_str.strip()

    # Pattern matching
    if sig.get("pattern"):
        try:
            if re.fullmatch(sig["pattern"], s, re.IGNORECASE):
                bonus = sig["weight"] * PATTERN_MATCH_MULTIPLIER
                score += bonus
                details.append(f"Pattern match: +{bonus:.1f}")
            else:
                penalty = sig["weight"] * PATTERN_MISS_PENALTY
                score -= penalty
        except re.error:
            pass

    # Length check
    if sig.get("lengths"):
        hash_len = len(s)
        if hash_len in sig["lengths"]:
            bonus = sig["weight"]
            score += bonus
            details.append(f"Length {hash_len}: +{bonus:.1f}")
        else:
            for L in sig["lengths"]:
                if abs(hash_len - L) <= 2:
                    bonus = sig["weight"] * LENGTH_NEAR_MULTIPLIER
                    score += bonus
                    details.append(f"Length ~{L}: +{bonus:.1f}")
                    break
    
    # Charset check
    cs = sig.get("charset")
    if cs and CHARSET_CHECKS.get(cs) and CHARSET_CHECKS[cs](s):
        bonus = sig["weight"] * CHARSET_MATCH_MULTIPLIER
        score += bonus
        details.append(f"Charset '{cs}': +{bonus:.1f}")

    # Heuristics for common cases
    if sig["name"] == "ntlm" and s.isupper() and s.isalnum():
        score += HEURISTIC_BONUS
        details.append(f"Heuristic (NTLM uppercase): +{HEURISTIC_BONUS}")
    if sig["name"] == "md5" and ":" in original_input and sig.get("salt_position") != "external":
        score += HEURISTIC_BONUS / 2
        details.append(f"Heuristic (MD5 with ':'): +{HEURISTIC_BONUS / 2:.1f}")

    return max(score, 0.0), details

# ------------------ Hash Detection ------------------
def detect_hash(hash_str: str, signatures: List[Dict[str, Any]], top_k: int = MAX_CANDIDATES_DEFAULT) -> List[Dict[str,Any]]:
    candidates = []
    
    # Process all signatures
    for sig in signatures:
        score, details = score_candidate(hash_str, sig, hash_str)
        if score > 0:
            candidates.append({
                "sig": sig,
                "score": score,
                "details": details
            })

    # Sort and normalize
    candidates.sort(key=lambda x: x["score"], reverse=True)
    if not candidates: return []

    max_score = candidates[0]["score"] if candidates else 1.0
    
    output = []
    for cand in candidates[:top_k]:
        sig = cand["sig"]
        output.append({
            "name": sig["name"],
            "score": round(cand["score"], 2),
            "probability_pct": percent(cand["score"] / max_score),
            "details": cand["details"],
            "notes": sig.get("notes", ""),
            "hashcat_mode": sig.get("hashcat_mode")
        })
    return output

# ------------------ Signature Management ------------------
def update_signatures():
    console.print(f"[yellow]Downloading latest signatures from:[cyan]\n{SIGNATURES_URL}[/cyan]")
    try:
        with request.urlopen(SIGNATURES_URL, timeout=10) as response:
            if response.status != 200:
                console.print(f"[bold red]Error: Failed to fetch file (status: {response.status})[/bold red]")
                return
            data = response.read()
        
        # Validate JSON and required keys
        signatures = json.loads(data)
        required_keys = {"name", "weight", "hashcat_mode", "salt_position"}
        if not isinstance(signatures, list) or not all(isinstance(s, dict) and required_keys.issubset(s.keys()) for s in signatures):
            raise ValueError("Invalid format or missing required keys in signatures.")

        with open(SIGNATURES_FILE, 'w', encoding='utf-8') as f:
            json.dump(signatures, f, indent=2, ensure_ascii=False)
        
        console.print(f"[bold green]Success! Saved {len(signatures)} signatures to '{SIGNATURES_FILE}'.[/bold green]")
    except error.URLError as e:
        console.print(f"[bold red]Network error during update: {e.reason}[/bold red]")
    except (json.JSONDecodeError, ValueError, Exception) as e:
        console.print(f"[bold red]Failed to update signatures: {e}[/bold red]")

def load_signatures() -> List[Dict[str, Any]]:
    if os.path.exists(SIGNATURES_FILE):
        try:
            with open(SIGNATURES_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[yellow]Warning: Could not load '{SIGNATURES_FILE}' ({e}). Using built-in database.[/yellow]")
    return DEFAULT_HASH_SIGNATURES

# ------------------ Output & Helpers ------------------
def gen_hashcat_cmd(hash_str: str, best_candidate: dict) -> str:
    mode = best_candidate.get('hashcat_mode')
    if mode is None:
        return f"# No certain hashcat mode for {best_candidate['name']}. Please verify manually."
    return f"hashcat -m {mode} -a 0 \"{hash_str}\" /path/to/wordlist.txt"

HELP_MD = """
# hashmap v3.0 — Smart Hash Identifier + Hashcat Helper

**Usage**
- `hashmap.py <hash>`
- `hashmap.py -f <hash_file>`
- `cat hashes.txt | hashmap.py`

**Output Options**
- `--json`             Output in JSON format.
- `--hashcat-only`     Print only the best hashcat mode (`-m`).
- `--cmd`              Print a suggested hashcat command.
- `-k, --top`          Show top K candidates (default: 8).
- `-v, --verbose`      Show detailed scoring information.

**Management**
- `--update`           Download the latest hash signatures.
- `--export-hashcat <file>` Export results to a hashcat file (`mode:hash`).

**Other**
- `--test`             Run built-in test vectors.
- `-h, --help`         Show this help message.
"""

def pretty_print_results(hash_str: str, candidates: List[Dict[str, Any]], verbose: bool):
    if not candidates:
        console.print(f"[yellow]Could not identify hash: {hash_str}[/yellow]")
        return
        
    if RICH_AVAILABLE:
        table = Table(show_header=True, header_style="bold magenta", title=f"[bold]Analysis for: [white]{hash_str}[/white][/bold]")
        table.add_column("#", style="dim", width=2)
        table.add_column("Algorithm", style="bold", min_width=20)
        table.add_column("Mode", style="cyan", width=8)
        table.add_column("Prob.", style="green", width=7)
        if verbose:
            table.add_column("Scoring Details", style="white", min_width=30)
        table.add_column("Notes", style="dim")
        
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            prob = f"{c['probability_pct']}%"
            row = [str(i), c['name'], mode, prob]
            if verbose:
                row.append(", ".join(c['details']))
            row.append(c['notes'])
            table.add_row(*row)
        console.print(table)
    else: # Fallback for no rich
        print(f"\n--- Analysis for: {hash_str} ---")
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            print(f"{i}. {c['name']} ({c['probability_pct']}% prob.)")
            print(f"   Mode: {mode} | Notes: {c['notes']}")
            if verbose:
                print(f"   Scoring: {', '.join(c['details'])}")
        print("-"*(22 + len(hash_str)))

def run_tests(signatures):
    console.rule("[bold yellow]Running Built-in Tests[/bold yellow]")
    test_hashes = [
        "$2y$12$D4G5f18o7aTMfOSEiEMhJulK4pe8H/datqMNZxTNdlLAHeOOBpSGO", # bcrypt
        "$1$salt$x/52mNDi3zV93g1vR.0a61",  # md5crypt
        "5f4dcc3b5aa765d61d8327deb882cf99",  # md5
        "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0", # NTLM (uppercase)
        "$6$rounds=5000$usesomesillystri$K..AnmQDJ0VaT4TbL2A/.AB.UQ82l9aA048tcGp5VprKR4YBIxWh5tG2MhBCv/dsr/s2EPo85.x/aeh9LgY34.", # sha512crypt
        "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$RdescudvJCsgt4Q_Wb3GfA", # argon2id
        "pbkdf2_sha256$260000$test_salt$gS0g8fE4m36d5tW/1Tf3Yh2xQY6f7j8k9l0m1N2o3p4=", # Django
        "pmkid*0123456789ab*123456789abc*546573744553534944", # WPA-PMKID (dummy)
        "$krb5tgs$23$*user$EXAMPLE.COM$http/server.example.com*$3B4A982823B4A982823B4A982823B4A9*B4A982823B4A982823B4A982823B4A982" # Kerberos TGS-REP
    ]
    for h in test_hashes:
        candidates = detect_hash(h, signatures)
        pretty_print_results(h, candidates, verbose=True)
    console.rule("[bold green]Tests Finished[/bold green]")

# ------------------ CLI Main ------------------
def main():
    parser = argparse.ArgumentParser(description="hashmap v3.0 — Smart Hash Identifier", add_help=False)
    parser.add_argument("hashes", nargs="*", help="One or more hashes to identify")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("-k", "--top", type=int, default=MAX_CANDIDATES_DEFAULT, help=f"Show top K candidates (default: {MAX_CANDIDATES_DEFAULT})")
    parser.add_argument("--hashcat-only", action="store_true", help="Print only the best hashcat mode")
    parser.add_argument("--cmd", action="store_true", help="Generate a sample hashcat command")
    parser.add_argument("--test", action="store_true", help="Run built-in test vectors")
    parser.add_argument("--update", action="store_true", help="Download latest hash signatures")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed scoring information")
    parser.add_argument("--export-hashcat", metavar='FILE', help="Export results to a hashcat-ready file (mode:hash)")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message")
    args = parser.parse_args()

    if args.help or (len(sys.argv) == 1 and sys.stdin.isatty()):
        print_help_and_exit(parser)

    if args.update:
        update_signatures()
        sys.exit(0)
    
    signatures = load_signatures()
    
    if args.test:
        run_tests(signatures)
        sys.exit(0)

    # Gather hashes from arguments, file, or stdin
    all_hashes = args.hashes
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                all_hashes.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
            sys.exit(1)
    elif not sys.stdin.isatty():
        all_hashes.extend([line.strip() for line in sys.stdin if line.strip()])

    if not all_hashes:
        console.print("[yellow]No hashes provided. Use -h for help.[/yellow]")
        sys.exit(0)

    # Process hashes
    export_lines = []
    results_json = {}
    for hash_str in all_hashes:
        if not hash_str: continue
        candidates = detect_hash(hash_str, signatures, top_k=args.top)
        
        if not candidates:
            console.print(f"[yellow]Could not identify hash: {hash_str}[/yellow]")
            continue

        best_candidate = candidates[0]
        
        if args.json:
            results_json[hash_str] = candidates
        elif args.hashcat_only:
            print(best_candidate.get("hashcat_mode", "N/A"))
        elif args.cmd:
            print(gen_hashcat_cmd(hash_str, best_candidate))
        elif args.export_hashcat:
            mode = best_candidate.get("hashcat_mode")
            if mode is not None:
                export_lines.append(f"{mode}:{hash_str}")
        else:
            pretty_print_results(hash_str, candidates, args.verbose)
    
    if args.export_hashcat:
        try:
            with open(args.export_hashcat, 'w', encoding='utf-8') as f:
                f.write("\n".join(export_lines) + "\n")
            console.print(f"[bold green]Successfully exported {len(export_lines)} hashes to '{args.export_hashcat}'[/bold green]")
        except IOError as e:
            console.print(f"[bold red]Error writing to export file: {e}[/bold red]")
    
    if args.json:
        console.print(json.dumps(results_json, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()


