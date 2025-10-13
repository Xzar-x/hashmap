#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashmap.py — A smart hash type identifier and hashcat helper
Version: 6.0 (Roadmap Implemented)
Author: Xzar
Description:
  - Implements all roadmap features: input filtering, tolerance-based results,
    priority scoring, NTLM heuristics, hash:salt parsing, and performance pre-filtering.
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
import time
from typing import List, Tuple, Dict, Any
from urllib import request, error
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
LENGTH_NEAR_MULTIPLIER = 0.12
CHARSET_MATCH_MULTIPLIER = 0.6
MAX_CANDIDATES_DEFAULT = 10 # Increased default for better tolerance results
LAST_UPDATE_FILE = ".hashmap_last_update"
SIGNATURES_URL = None # URL for remote signatures. You can host the JSON on a Gist and paste the link here.

# --- Dynamic path resolution for the signatures file ---
try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    SIGNATURES_FILE = os.path.join(SCRIPT_DIR, "hashmap_signatures.json")
except NameError:
    SIGNATURES_FILE = "hashmap_signatures.json"


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
    return len(s) % 4 == 0

def percent(x: float) -> float:
    return round(x * 100, 2)

# ZMIANA (Punkt 1): Filtrowanie wejścia
def is_valid_hash_line(line: str) -> bool:
    s = line.strip()
    if len(s) < 16: return False
    if any(word in s.lower() for word in ['hashes', 'analysis', 'hash:', '(cd', '---']): return False
    if s.count(' ') > 2: return False
    if any(char in s for char in ['(', ')']): return False
    return True

# ZMIANA (Punkt 2): Zwracanie podobnych kandydatów
def get_similar_candidates(candidates: List[Dict], tolerance_pct: float = 15.0) -> List[Dict]:
    if not candidates: return []
    best_score = candidates[0]['score']
    if best_score == 0: return [c for c in candidates if c['score'] == 0]
    threshold = best_score * (1 - tolerance_pct / 100)
    return [c for c in candidates if c['score'] >= threshold]

# ZMIANA (Punkt 4): Heurystyka NTLM vs MD5
def apply_ntlm_heuristics(hash_str: str, sig: dict, details: List[str]) -> float:
    bonus = 0.0
    s = hash_str.lower()
    sig_name = sig.get("name", "").lower()

    if "ntlm" in sig_name:
        if not re.search(r'(.)\1{3,}', s):
            bonus += 3
            details.append("NTLM hint (low repetition): +3")
    elif "md5" in sig_name:
        if re.search(r'(.)\1{4,}', s):
            bonus -= 4
            details.append("Less likely MD5 (high repetition): -4")
    return bonus

# ZMIANA (Punkt 6): Obsługa formatu hash:salt
def split_hash_salt(line: str) -> Tuple[str, str]:
    parts = line.strip().split(':')
    if len(parts) == 2:
        hash_part, salt_part = parts
        if len(hash_part) > len(salt_part) and len(salt_part) > 0:
            return hash_part, salt_part
    return line.strip(), ""

# ZMIANA (Punkt 7): Pre-filtr po długości
def get_candidates_by_length(hash_len: int, signatures: List[Dict]) -> List[Dict]:
    candidates = []
    for sig in signatures:
        lengths = sig.get("lengths", [])
        if lengths:
            if hash_len in lengths or any(abs(hash_len - L) <= 2 for L in lengths):
                candidates.append(sig)
        elif sig.get("pattern"):
            candidates.append(sig)
    return candidates

# ------------------ Scoring Engine (v6.0) ------------------
def score_candidate(hash_str: str, sig: dict) -> Tuple[float, List[str]]:
    score = 0.0
    details: List[str] = []
    s = hash_str.strip()

    if sig.get("pattern"):
        try:
            if re.fullmatch(sig["pattern"], s, re.IGNORECASE):
                bonus = sig["weight"] * PATTERN_MATCH_MULTIPLIER
                score += bonus
                details.append(f"Pattern: +{bonus:.1f}")
        except re.error:
            pass

    if sig.get("lengths"):
        hash_len = len(s)
        if hash_len in sig["lengths"]:
            bonus = sig["weight"]
            score += bonus
            details.append(f"Length ({hash_len}): +{bonus:.1f}")
        else:
            for L in sig["lengths"]:
                if abs(hash_len - L) <= 2:
                    bonus = sig["weight"] * LENGTH_NEAR_MULTIPLIER
                    score += bonus
                    details.append(f"Near length (~{L}): +{bonus:.1f}")
                    break
    
    cs = sig.get("charset")
    if cs and CHARSET_CHECKS.get(cs) and CHARSET_CHECKS[cs](s):
        bonus = sig["weight"] * CHARSET_MATCH_MULTIPLIER
        score += bonus
        details.append(f"Charset ('{cs}'): +{bonus:.1f}")

    # ZMIANA (Punkt 3): Bonus za priorytet
    priority = sig.get("priority", 50)
    priority_bonus = (priority - 50) * 0.3
    score += priority_bonus
    if abs(priority_bonus) > 0.1:
        details.append(f"Priority ({priority}): {priority_bonus:+.1f}")
    
    # ZMIANA (Punkt 4): Dodaj heurystykę
    heuristic_bonus = apply_ntlm_heuristics(hash_str, sig, details)
    score += heuristic_bonus
    
    return max(score, 0.0), details

# ------------------ Hash Detection ------------------
def detect_hash(input_str: str, signatures: List[Dict[str, Any]], top_k: int = MAX_CANDIDATES_DEFAULT) -> List[Dict[str,Any]]:
    
    # ZMIANA (Punkt 6): Podziel na hash i salt
    hash_part, salt_part = split_hash_salt(input_str)

    # ZMIANA (Punkt 7): Prefiltrowanie
    prefiltered_sigs = get_candidates_by_length(len(hash_part), signatures)

    candidates = []
    for sig in prefiltered_sigs:
        score, details = score_candidate(hash_part, sig)
        
        # ZMIANA (Punkt 6): Bonus/kara za sól
        if salt_part:
            salt_pos = sig.get("salt_position", "none")
            if salt_pos != "none":
                score *= 1.2
                details.append(f"Salt detected: ×1.2")
            else:
                score *= 0.5
                details.append(f"Salt unexpected: ×0.5")

        if score > 0:
            candidates.append({ "sig": sig, "score": score, "details": details })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    if not candidates: return []

    max_score = candidates[0]["score"] if candidates else 1.0
    
    output = []
    for cand in candidates[:top_k]:
        sig = cand["sig"]
        prob = percent(min(cand["score"] / (max_score * 1.05), 1.0)) if max_score > 0 else 0.0

        if prob >= 0:
            output.append({
                "name": sig["name"],
                "score": round(cand["score"], 2),
                "probability_pct": prob,
                "details": cand["details"],
                "notes": sig.get("notes", ""),
                "hashcat_mode": sig.get("hashcat_mode")
            })
    return output

# ------------------ Signature Management ------------------
def load_signatures() -> List[Dict[str, Any]]:
    if not os.path.exists(SIGNATURES_FILE):
        console.print(f"[bold red]Critical Error: Signatures file '{os.path.basename(SIGNATURES_FILE)}' not found.[/bold red]")
        sys.exit(1)
    try:
        with open(SIGNATURES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        console.print(f"[bold red]Error: Could not load signatures file '{os.path.basename(SIGNATURES_FILE)}' ({e}).[/bold red]")
        sys.exit(1)

# ------------------ Output & Helpers ------------------
def gen_hashcat_cmd(hash_str: str, best_candidate: dict) -> str:
    mode = best_candidate.get('hashcat_mode')
    if mode is None:
        return f"# No certain hashcat mode for {best_candidate['name']}. Please verify manually."
    return f"hashcat -m {mode} -a 0 \"{hash_str}\" /path/to/wordlist.txt"

HELP_MD = """
# hashmap v6.0 — Smart Hash Identifier + Hashcat Helper

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

def print_help_and_exit(parser: argparse.ArgumentParser):
    if RICH_AVAILABLE:
        console.print(Panel(Markdown(HELP_MD), title="[bold]hashmap v6.0 — Help[/bold]", expand=False, border_style="blue"))
    else:
        print(HELP_MD)
    sys.exit(0)

def pretty_print_results(hash_str: str, candidates: List[Dict[str, Any]], verbose: bool):
    if not candidates:
        console.print(f"[yellow]Could not identify hash: {hash_str}[/yellow]")
        return
        
    if RICH_AVAILABLE:
        title = f"[bold]Analysis for: [white]{hash_str if len(hash_str) < 80 else hash_str[:77]+'...'}[/white][/bold]"
        table = Table(show_header=True, header_style="bold magenta", title=title)
        table.add_column("#", style="dim", width=2)
        table.add_column("Algorithm", style="bold", min_width=20)
        table.add_column("Mode", style="cyan", width=8)
        table.add_column("Score", style="yellow", width=8)
        if verbose:
            table.add_column("Scoring Details", style="white", min_width=30)
        table.add_column("Notes", style="dim")
        
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            score = f"{c['score']:.1f}"
            row_items = [str(i), c['name'], mode, score]
            if verbose:
                row_items.append(", ".join(c['details']))
            row_items.append(c['notes'])
            table.add_row(*row_items)
        console.print(table)
    else:
        print(f"\n--- Analysis for: {hash_str} ---")
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            print(f"{i}. {c['name']} (Score: {c['score']:.1f})")
            print(f"   Mode: {mode} | Notes: {c['notes']}")
        print("-"*(22 + len(hash_str)))

# ------------------ CLI Main ------------------
def main():
    parser = argparse.ArgumentParser(description="hashmap v6.0 — Smart Hash Identifier", add_help=False)
    parser.add_argument("hashes", nargs="*", help="One or more hashes to identify")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("-k", "--top", type=int, default=MAX_CANDIDATES_DEFAULT, help=f"Show top K candidates (default: {MAX_CANDIDATES_DEFAULT})")
    parser.add_argument("--hashcat-only", action="store_true", help="Print only the best hashcat mode")
    parser.add_argument("--cmd", action="store_true", help="Generate a sample hashcat command")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed scoring information")
    
    # ZMIANA (Punkt 8 i 2): Nowe argumenty CLI
    parser.add_argument('--tolerance', type=float, default=15.0, help='Show candidates within N%% of top score (def: 15%%)')
    parser.add_argument('--strict', action='store_true', help='Show only best match (ignores tolerance)')
    parser.add_argument('--min-weight', type=int, default=0, help='Ignore signatures with weight < N')
    
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message")
    args = parser.parse_args()

    if args.help or (len(sys.argv) == 1 and sys.stdin.isatty()):
        print_help_and_exit(parser)
    
    signatures = load_signatures()
    
    # ZMIANA (Punkt 8): Filtrowanie sygnatur po wadze
    if args.min_weight > 0:
        signatures = [s for s in signatures if s.get('weight', 0) >= args.min_weight]

    all_hashes = args.hashes
    # ZMIANA (Punkt 1): Filtrowanie linii wejściowych
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                all_hashes.extend([line.strip() for line in f if is_valid_hash_line(line)])
        except FileNotFoundError:
            console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
            sys.exit(1)
    elif not sys.stdin.isatty():
        stdin_data = sys.stdin.read()
        all_hashes.extend([line.strip() for line in stdin_data.splitlines() if is_valid_hash_line(line)])
    
    all_hashes = [h for h in all_hashes if is_valid_hash_line(h)]

    if not all_hashes:
        console.print("[yellow]No valid hashes provided. Use -h for help.[/yellow]")
        sys.exit(0)
    
    results_json = {}
    for hash_str in all_hashes:
        if not hash_str: continue
        
        candidates = detect_hash(hash_str, signatures, top_k=args.top)
        
        if not candidates:
            if not args.json:
                console.print(f"[yellow]Could not identify hash: {hash_str}[/yellow]")
            continue
        
        # ZMIANA (Punkt 2): Zastosowanie tolerancji lub trybu strict
        if args.strict:
            final_candidates = candidates[:1]
        else:
            final_candidates = get_similar_candidates(candidates, args.tolerance)
        
        if not final_candidates:
             if not args.json:
                console.print(f"[yellow]No candidates for hash: {hash_str} within tolerance[/yellow]")
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


