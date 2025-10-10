#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashmap.py — A smart hash type identifier and hashcat helper
Version: 5.0 (Full English translation, dynamic pathing for portability)
Author: Xzar
Description:
  - Signature database with over 150 hash types loaded from an external JSON file.
  - New --cluster feature to group hashes from input files.
  - Dynamic path resolution makes the script portable and easy to install system-wide.
  - Structure prepared for future Machine Learning model integration.
Usage:
  hashmap <hash>
  hashmap -f <hash_file> --cluster
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
HEURISTIC_BONUS = 25.0
MAX_CANDIDATES_DEFAULT = 8
LAST_UPDATE_FILE = ".hashmap_last_update"
SIGNATURES_URL = None # URL for remote signatures. You can host the JSON on a Gist and paste the link here.

# --- Dynamic path resolution for the signatures file ---
# This ensures the script always finds its JSON file, regardless of where it's run from.
try:
    # __file__ is a special Python variable holding the path to the current script
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    SIGNATURES_FILE = os.path.join(SCRIPT_DIR, "hashmap_signatures.json")
except NameError:
    # Fallback if __file__ is not defined (e.g., in an interactive interpreter)
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

# ------------------ Future ML Enhancement Stub ------------------
def ml_confidence_boost(hash_str: str, top_candidate: Dict) -> float:
    """
    STUB FOR A FUTURE ML MODEL
    This function could use a trained model to analyze statistical properties
    of the hash that are not captured by regex or length checks.

    Example features for the model:
    - Byte distribution (entropy)
    - Frequency of specific characters
    - Ratio of letters to numbers
    - Presence of specific sequences at certain positions

    The model (e.g., Logistic Regression, RandomForest, small neural network)
    could return an additional confidence score (e.g., from -0.2 to +0.2)
    to adjust the final probability.
    """
    # For now, the function does nothing and returns a neutral value.
    return 0.0

# ------------------ Scoring Engine (v5.0) ------------------
def score_candidate(hash_str: str, sig: dict, original_input: str) -> Tuple[float, List[str]]:
    score = 0.0
    details: List[str] = []
    s = hash_str.strip()

    if sig.get("pattern"):
        try:
            if re.fullmatch(sig["pattern"], s, re.IGNORECASE):
                bonus = sig["weight"] * PATTERN_MATCH_MULTIPLIER
                score += bonus
                details.append(f"Pattern match: +{bonus:.1f}")
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

    if sig["name"] == "NTLM" and s.isupper() and s.isalnum():
        score += HEURISTIC_BONUS
        details.append(f"Heuristic (NTLM uppercase): +{HEURISTIC_BONUS}")
    if sig["name"] == "MD5" and ":" in original_input and sig.get("salt_position") == "none":
        score -= HEURISTIC_BONUS
        details.append(f"Heuristic (MD5 with ':' penalty): -{HEURISTIC_BONUS:.1f}")

    return max(score, 0.0), details

# ------------------ Hash Detection ------------------
def detect_hash(hash_str: str, signatures: List[Dict[str, Any]], top_k: int = MAX_CANDIDATES_DEFAULT, min_confidence: float = 0.0) -> List[Dict[str,Any]]:
    candidates = []
    
    for sig in signatures:
        score, details = score_candidate(hash_str, sig, hash_str)
        if score > 0:
            candidates.append({
                "sig": sig,
                "score": score,
                "details": details
            })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    if not candidates: return []

    max_score = candidates[0]["score"] if candidates else 1.0
    
    output = []
    for cand in candidates[:top_k]:
        sig = cand["sig"]
        prob = percent(min(cand["score"] / (max_score * 1.05), 1.0))

        # Potential hook for ML boost
        # ml_boost = ml_confidence_boost(hash_str, cand)
        # prob = max(0, min(100, prob + (ml_boost * 100)))

        if prob >= min_confidence:
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
def update_signatures():
    if SIGNATURES_URL is None:
        console.print("[yellow]Auto-update is disabled. No SIGNATURES_URL is provided.[/yellow]")
        return
        
    if os.path.exists(LAST_UPDATE_FILE):
        try:
            with open(LAST_UPDATE_FILE, 'r') as f:
                last_update_time = float(f.read())
            if time.time() - last_update_time < 3600: # 1 hour cooldown
                console.print("[yellow]Last update was less than 1 hour ago. Skipping.[/yellow]")
                return
        except (ValueError, IOError):
            pass

    console.print(f"[yellow]Downloading latest signatures from:[cyan]\n{SIGNATURES_URL}[/cyan]")
    try:
        with request.urlopen(SIGNATURES_URL, timeout=15) as response:
            if response.status != 200:
                console.print(f"[bold red]Error: Failed to fetch file (status: {response.status})[/bold red]")
                return
            data = response.read()
        
        signatures = json.loads(data)
        required_keys = {"name", "weight", "hashcat_mode"}
        if not isinstance(signatures, list) or not all(isinstance(s, dict) and required_keys.issubset(s.keys()) for s in signatures):
            raise ValueError("Invalid format or missing required keys in signatures.")

        with open(SIGNATURES_FILE, 'w', encoding='utf-8') as f:
            json.dump(signatures, f, indent=2, ensure_ascii=False)
        
        with open(LAST_UPDATE_FILE, 'w') as f:
            f.write(str(time.time()))
        console.print(f"[bold green]Success! Saved {len(signatures)} signatures to '{os.path.basename(SIGNATURES_FILE)}'.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to update signatures: {e}[/bold red]")


def load_signatures() -> List[Dict[str, Any]]:
    if not os.path.exists(SIGNATURES_FILE):
        console.print(f"[bold red]Critical Error: Signatures file '{os.path.basename(SIGNATURES_FILE)}' not found.[/bold red]")
        console.print(f"Please ensure `hashmap_signatures.json` is in the same directory as the script: {os.path.dirname(SIGNATURES_FILE)}")
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
# hashmap v5.0 — Smart Hash Identifier + Hashcat Helper

**Usage**
- `hashmap <hash>`
- `hashmap -f <hash_file>`
- `cat hashes.txt | hashmap`

**Output Options**
- `--json`             Output in JSON format.
- `--hashcat-only`     Print only the best hashcat mode (`-m`).
- `--cmd`              Print a suggested hashcat command.
- `-k, --top`          Show top K candidates (default: 8).
- `-v, --verbose`      Show detailed scoring information.
- `--min-confidence`   Minimum probability % to show (default: 0.0).

**File Analysis**
- `--cluster`          Group hashes from a file by type and show summary.
- `--export-hashcat <file>` Export results to a hashcat file (`mode:hash`).

**Management**
- `--update`           Download the latest hash signatures (1h cooldown).
- `--test`             Run built-in test vectors.
- `-h, --help`         Show this help message.
"""

def print_help_and_exit(parser: argparse.ArgumentParser):
    if RICH_AVAILABLE:
        console.print(Panel(Markdown(HELP_MD), title="[bold]hashmap v5.0 — Help[/bold]", expand=False, border_style="blue"))
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
        table.add_column("Prob.", style="green", width=7)
        if verbose:
            table.add_column("Scoring Details", style="white", min_width=30)
        table.add_column("Notes", style="dim")
        
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            prob = f"{c['probability_pct']}%"
            row_items = [str(i), c['name'], mode, prob]
            if verbose:
                row_items.append(", ".join(c['details']))
            row_items.append(c['notes'])
            table.add_row(*row_items)
        console.print(table)
    else: # Fallback
        print(f"\n--- Analysis for: {hash_str} ---")
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            print(f"{i}. {c['name']} ({c['probability_pct']}% prob.)")
            print(f"   Mode: {mode} | Notes: {c['notes']}")
        print("-"*(22 + len(hash_str)))

def detect_hash_family(all_hashes: List[str], signatures: List[Dict[str, Any]]):
    """Groups hashes and displays a summary."""
    console.rule("[bold cyan]Hash Family Cluster Analysis[/bold cyan]")
    
    hash_families = Counter()
    unidentified_count = 0
    
    for h in all_hashes:
        candidates = detect_hash(h, signatures, top_k=1)
        if candidates:
            best_guess = candidates[0]['name']
            hash_families[best_guess] += 1
        else:
            unidentified_count += 1
            
    if not hash_families:
        console.print("[yellow]Could not identify any hash types in the provided file.[/yellow]")
        return

    table = Table(title="[bold]Hash Type Summary[/bold]")
    table.add_column("Hash Type", style="bold", min_width=30)
    table.add_column("Count", style="green", justify="right")
    
    for family, count in hash_families.most_common():
        table.add_row(family, str(count))
        
    if unidentified_count > 0:
        table.add_row("[dim]Unidentified[/dim]", f"[yellow]{unidentified_count}[/yellow]")
    
    console.print(table)


# ------------------ CLI Main ------------------
def main():
    parser = argparse.ArgumentParser(description="hashmap v5.0 — Smart Hash Identifier", add_help=False)
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
    parser.add_argument("--cluster", action="store_true", help="Group hashes from a file by type and show summary")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="Minimum probability %% to show")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message")
    args = parser.parse_args()

    if args.help or (len(sys.argv) == 1 and sys.stdin.isatty()):
        print_help_and_exit(parser)

    if args.update:
        update_signatures()
        sys.exit(0)
    
    signatures = load_signatures()
    
    if args.test:
        console.print("[yellow]--test feature is not yet implemented in this version.[/yellow]")
        sys.exit(0)

    all_hashes = args.hashes
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                all_hashes.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
            sys.exit(1)
    elif not sys.stdin.isatty():
        stdin_data = sys.stdin.read()
        all_hashes.extend([line.strip() for line in stdin_data.splitlines() if line.strip()])

    if not all_hashes:
        console.print("[yellow]No hashes provided. Use -h for help.[/yellow]")
        sys.exit(0)
    
    if args.cluster:
        detect_hash_family(all_hashes, signatures)
        sys.exit(0)

    export_lines = []
    results_json = {}
    for hash_str in all_hashes:
        if not hash_str: continue
        candidates = detect_hash(hash_str, signatures, top_k=args.top, min_confidence=args.min_confidence)
        
        if not candidates:
            if not args.json:
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


