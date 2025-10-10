#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashmap.py — inteligentny detektor typów hashy + helper hashcat
Wersja: 4.0 (potężna baza sygnatur, refaktoryzacja, architektura oparta na JSON)
Autor: Xzar (z rozszerzeniami Gemini na podstawie feedbacku użytkownika)
Opis:
  - Baza sygnatur z ponad 150 typami hashy w zewnętrznym pliku JSON
  - Architektura ułatwiająca aktualizację i rozszerzanie bazy
  - Tryb auto-update (--update) z walidacją i rate-limiting
  - Tryb verbose (-v) pokazujący szczegóły scoringu
  - Eksport do formatu hashcat (--export-hashcat)
  - Poprawiony scoring i tryby hashcat
  - Nowe opcje: --benchmark, --min-confidence
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
import time
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
LAST_UPDATE_FILE = ".hashmap_last_update"

# URL do sygnatur. Możesz w przyszłości umieścić plik JSON na Gist i wkleić tutaj link.
SIGNATURES_URL = None

CHARSET_CHECKS = {
    "hex": lambda s: bool(re.fullmatch(r"[0-9a-f]+", s, re.IGNORECASE)),
    "hex_upper": lambda s: bool(re.fullmatch(r"[0-9A-F]+", s)),
    "radix64": lambda s: bool(re.fullmatch(r"[A-Za-z0-9./$*=\-_\+]+", s)),
    "base64": lambda s: is_base64(s),
    "ascii": lambda s: all(32 <= ord(ch) <= 126 for ch in s),
}

# ---------------- Helper Functions ----------------
def is_base64(s: str) -> bool:
    """Sprawdza, czy ciąg jest poprawnym (lub prawdopodobnym) Base64."""
    if not isinstance(s, str) or not s or not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    # Podstawowe sprawdzenie bez dekodowania jest wystarczająco szybkie i skuteczne dla detekcji
    return len(s) % 4 == 0

def percent(x: float) -> float:
    return round(x * 100, 2)

# ------------------ Scoring Engine (v4.0) ------------------
def score_candidate(hash_str: str, sig: dict, original_input: str) -> Tuple[float, List[str]]:
    score = 0.0
    details: List[str] = []
    s = hash_str.strip()

    # Pattern matching - najwyższy priorytet
    if sig.get("pattern"):
        try:
            if re.fullmatch(sig["pattern"], s, re.IGNORECASE):
                bonus = sig["weight"] * PATTERN_MATCH_MULTIPLIER
                score += bonus
                details.append(f"Wzorzec pasuje: +{bonus:.1f}")
            else:
                # Nie nakładamy kary, jeśli wzorzec nie pasuje, bo wiele hashy go nie ma
                pass
        except re.error:
            pass # Ignoruj błędne regexy w sygnaturach

    # Sprawdzenie długości
    if sig.get("lengths"):
        hash_len = len(s)
        if hash_len in sig["lengths"]:
            bonus = sig["weight"]
            score += bonus
            details.append(f"Długość ({hash_len}): +{bonus:.1f}")
        else:
            # Sprawdź, czy długość jest bliska
            for L in sig["lengths"]:
                if abs(hash_len - L) <= 2:
                    bonus = sig["weight"] * LENGTH_NEAR_MULTIPLIER
                    score += bonus
                    details.append(f"Długość bliska (~{L}): +{bonus:.1f}")
                    break
    
    # Sprawdzenie zestawu znaków
    cs = sig.get("charset")
    if cs and CHARSET_CHECKS.get(cs) and CHARSET_CHECKS[cs](s):
        bonus = sig["weight"] * CHARSET_MATCH_MULTIPLIER
        score += bonus
        details.append(f"Zestaw znaków ('{cs}'): +{bonus:.1f}")

    # Heurystyki dla popularnych przypadków
    if sig["name"] == "NTLM" and s.isupper() and s.isalnum():
        score += HEURISTIC_BONUS
        details.append(f"Heurystyka (NTLM wielkie litery): +{HEURISTIC_BONUS}")
    if sig["name"] == "MD5" and ":" in original_input and sig.get("salt_position") == "none":
        score -= HEURISTIC_BONUS
        details.append(f"Heurystyka (MD5 z ':' w wejściu): -{HEURISTIC_BONUS:.1f}")
    if sig.get("hashcat_mode") == 0 and len(s) == 32 and CHARSET_CHECKS["hex"](s):
        score += 10 # Mały bonus dla MD5 jako domyślnego dla 32-znakowych hexów
        details.append("Heurystyka (popularny MD5): +10.0")

    return max(score, 0.0), details

# ------------------ Hash Detection ------------------
def detect_hash(hash_str: str, signatures: List[Dict[str, Any]], top_k: int = MAX_CANDIDATES_DEFAULT, min_confidence: float = 0.0) -> List[Dict[str,Any]]:
    candidates = []
    
    # Przetwórz wszystkie sygnatury
    for sig in signatures:
        score, details = score_candidate(hash_str, sig, hash_str)
        if score > 0:
            candidates.append({
                "sig": sig,
                "score": score,
                "details": details
            })

    # Sortuj i normalizuj wyniki
    candidates.sort(key=lambda x: x["score"], reverse=True)
    if not candidates: return []

    max_score = candidates[0]["score"] if candidates else 1.0
    
    output = []
    for cand in candidates[:top_k]:
        sig = cand["sig"]
        # Prawdopodobieństwo jest teraz bardziej realistyczne
        prob = percent(min(cand["score"] / (max_score * 1.05), 1.0))
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
        console.print("[yellow]Auto-aktualizacja wyłączona. Brak zdefiniowanego URL do sygnatur.[/yellow]")
        return
        
    if os.path.exists(LAST_UPDATE_FILE):
        try:
            with open(LAST_UPDATE_FILE, 'r') as f:
                last_update_time = float(f.read())
            if time.time() - last_update_time < 3600: # 1 godzina cooldownu
                console.print("[yellow]Ostatnia aktualizacja była mniej niż godzinę temu. Pomijam.[/yellow]")
                return
        except (ValueError, IOError):
            pass # Ignoruj błędy w pliku

    console.print(f"[yellow]Pobieranie najnowszych sygnatur z:[cyan]\n{SIGNATURES_URL}[/cyan]")
    try:
        with request.urlopen(SIGNATURES_URL, timeout=15) as response:
            if response.status != 200:
                console.print(f"[bold red]Błąd: Nie udało się pobrać pliku (status: {response.status})[/bold red]")
                return
            data = response.read()
        
        # Walidacja JSON i wymaganych kluczy
        signatures = json.loads(data)
        required_keys = {"name", "weight", "hashcat_mode"}
        if not isinstance(signatures, list) or not all(isinstance(s, dict) and required_keys.issubset(s.keys()) for s in signatures):
            raise ValueError("Nieprawidłowy format lub brak wymaganych kluczy w sygnaturach.")

        with open(SIGNATURES_FILE, 'w', encoding='utf-8') as f:
            json.dump(signatures, f, indent=2, ensure_ascii=False)
        
        with open(LAST_UPDATE_FILE, 'w') as f:
            f.write(str(time.time()))

        console.print(f"[bold green]Sukces! Zapisano {len(signatures)} sygnatur do '{SIGNATURES_FILE}'.[/bold green]")
    except error.URLError as e:
        console.print(f"[bold red]Błąd sieci podczas aktualizacji: {e.reason}[/bold red]")
    except (json.JSONDecodeError, ValueError, Exception) as e:
        console.print(f"[bold red]Nie udało się zaktualizować sygnatur: {e}[/bold red]")

def load_signatures() -> List[Dict[str, Any]]:
    """Ładuje sygnatury z pliku JSON lub zwraca domyślne, jeśli plik nie istnieje."""
    if os.path.exists(SIGNATURES_FILE):
        try:
            with open(SIGNATURES_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[yellow]Ostrzeżenie: Nie można wczytać '{SIGNATURES_FILE}' ({e}). Sprawdź, czy plik istnieje i jest poprawny.[/yellow]")
            sys.exit(1)
    else:
        console.print(f"[yellow]Plik '{SIGNATURES_FILE}' nie został znaleziony. Upewnij się, że znajduje się w tym samym katalogu co skrypt.[/yellow]")
        sys.exit(1)


# ------------------ Output & Helpers ------------------
def gen_hashcat_cmd(hash_str: str, best_candidate: dict) -> str:
    mode = best_candidate.get('hashcat_mode')
    if mode is None:
        return f"# Brak pewnego trybu hashcat dla {best_candidate['name']}. Sprawdź manualnie."
    return f"hashcat -m {mode} -a 0 \"{hash_str}\" /path/to/wordlist.txt"

HELP_MD = """
# hashmap v4.0 — Smart Hash Identifier + Hashcat Helper

**Użycie**
- `hashmap.py <hash>`
- `hashmap.py -f <plik_z_hashami>`
- `cat hashes.txt | hashmap.py`

**Opcje wyjścia**
- `--json`             Wyjście w formacie JSON.
- `--hashcat-only`     Wyświetl tylko najlepszy tryb hashcat (`-m`).
- `--cmd`              Wyświetl sugerowaną komendę hashcat.
- `-k, --top`          Pokaż K najlepszych kandydatów (domyślnie: 8).
- `-v, --verbose`      Pokaż szczegółowe informacje o punktacji.
- `--min-confidence`   Minimalne prawdopodobieństwo % do pokazania (domyślnie: 0.0).

**Zarządzanie**
- `--update`           Pobierz najnowsze sygnatury hashy (cooldown 1h).
- `--export-hashcat <plik>` Eksportuj wyniki do pliku hashcat (`tryb:hash`).

**Inne**
- `--benchmark`        Tryb benchmarku (mierzenie czasu dla dużych list).
- `--test`             Uruchom wbudowane testy.
- `-h, --help`         Pokaż tę wiadomość.
"""

def print_help_and_exit(parser: argparse.ArgumentParser):
    if RICH_AVAILABLE:
        console.print(Panel(Markdown(HELP_MD), title="[bold]hashmap v4.0 — pomoc[/bold]", expand=False, border_style="blue"))
    else:
        print(HELP_MD)
    sys.exit(0)

def pretty_print_results(hash_str: str, candidates: List[Dict[str, Any]], verbose: bool):
    if not candidates:
        console.print(f"[yellow]Nie udało się zidentyfikować hasha: {hash_str}[/yellow]")
        return
        
    if RICH_AVAILABLE:
        table = Table(show_header=True, header_style="bold magenta", title=f"[bold]Analiza dla: [white]{hash_str}[/white][/bold]")
        table.add_column("#", style="dim", width=2)
        table.add_column("Algorytm", style="bold", min_width=20)
        table.add_column("Tryb", style="cyan", width=8)
        table.add_column("Prawd.", style="green", width=7)
        if verbose:
            table.add_column("Szczegóły scoringu", style="white", min_width=30)
        table.add_column("Notatki", style="dim")
        
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            prob = f"{c['probability_pct']}%"
            row = [str(i), c['name'], mode, prob]
            if verbose:
                row.append(", ".join(c['details']))
            row.append(c['notes'])
            table.add_row(*row)
        console.print(table)
    else: # Fallback
        print(f"\n--- Analiza dla: {hash_str} ---")
        for i, c in enumerate(candidates, 1):
            mode = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "N/A"
            print(f"{i}. {c['name']} ({c['probability_pct']}% prawd.)")
            print(f"   Tryb: {mode} | Notatki: {c['notes']}")
            if verbose:
                print(f"   Scoring: {', '.join(c['details'])}")
        print("-"*(22 + len(hash_str)))

def run_tests(signatures):
    console.rule("[bold yellow]Uruchamianie wbudowanych testów[/bold yellow]")
    test_hashes = [
        # Przykłady z oryginalnego skryptu
        "$2y$12$D4G5f18o7aTMfOSEiEMhJulK4pe8H/datqMNZxTNdlLAHeOOBpSGO", # bcrypt
        "$1$salt$x/52mNDi3zV93g1vR.0a61",  # md5crypt
        "5f4dcc3b5aa765d61d8327deb882cf99",  # md5
        "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0", # NTLM (uppercase)
        "$6$rounds=5000$usesomesillystri$K..AnmQDJ0VaT4TbL2A/.AB.UQ82l9aA048tcGp5VprKR4YBIxWh5tG2MhBCv/dsr/s2EPo85.x/aeh9LgY34.", # sha512crypt
        "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$RdescudvJCsgt4Q_Wb3GfA", # argon2id
        "pbkdf2_sha256$260000$test_salt$gS0g8fE4m36d5tW/1Tf3Yh2xQY6f7j8k9l0m1N2o3p4=", # Django
        # Nowe testy
        "098f6bcd4621d373cade4e832627b4f6", # md5('test')
        "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", # sha1('test')
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", # sha256('test')
        "7z'0*20*2*...*2807b1d1f050212002b55f10b7405d45*831a28a16827", # 7-Zip
        "$RAR3$*0*...*f83214f40102b55f", # RAR3-hp
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" # JWT
    ]
    for h in test_hashes:
        # Skracamy długie hashe do wyświetlania
        display_h = h if len(h) < 70 else h[:67] + "..."
        candidates = detect_hash(h, signatures)
        pretty_print_results(display_h, candidates, verbose=False) # Zmienione na False dla zwięzłości
    console.rule("[bold green]Testy zakończone[/bold green]")


# ------------------ CLI Main ------------------
def main():
    parser = argparse.ArgumentParser(description="hashmap v4.0 — Smart Hash Identifier", add_help=False)
    parser.add_argument("hashes", nargs="*", help="Jeden lub więcej hashy do identyfikacji")
    parser.add_argument("-f", "--file", help="Plik z jednym hashem w linii")
    parser.add_argument("--json", action="store_true", help="Wyjście w formacie JSON")
    parser.add_argument("-k", "--top", type=int, default=MAX_CANDIDATES_DEFAULT, help=f"Pokaż K najlepszych kandydatów (domyślnie: {MAX_CANDIDATES_DEFAULT})")
    parser.add_argument("--hashcat-only", action="store_true", help="Wyświetl tylko najlepszy tryb hashcat")
    parser.add_argument("--cmd", action="store_true", help="Wygeneruj przykładową komendę hashcat")
    parser.add_argument("--test", action="store_true", help="Uruchom wbudowane testy")
    parser.add_argument("--update", action="store_true", help="Pobierz najnowsze sygnatury hashy")
    parser.add_argument("-v", "--verbose", action="store_true", help="Pokaż szczegółowe informacje o punktacji")
    parser.add_argument("--export-hashcat", metavar='FILE', help="Eksportuj wyniki do pliku gotowego dla hashcat (tryb:hash)")
    parser.add_argument("--benchmark", action="store_true", help="Tryb benchmarku (mierzenie czasu)")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="Minimalne prawdopodobieństwo %% do pokazania")
    parser.add_argument("-h", "--help", action="store_true", help="Pokaż tę wiadomość")
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

    # Zbierz hashe z argumentów, pliku lub stdin
    all_hashes = args.hashes
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                all_hashes.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[bold red]Błąd: Plik nie został znaleziony: {args.file}[/bold red]")
            sys.exit(1)
    elif not sys.stdin.isatty():
        stdin_data = sys.stdin.read()
        all_hashes.extend([line.strip() for line in stdin_data.splitlines() if line.strip()])

    if not all_hashes:
        console.print("[yellow]Nie podano żadnych hashy. Użyj -h po pomoc.[/yellow]")
        sys.exit(0)
    
    start_time = time.time()
    
    # Przetwarzaj hashe
    export_lines = []
    results_json = {}
    for hash_str in all_hashes:
        if not hash_str: continue
        candidates = detect_hash(hash_str, signatures, top_k=args.top, min_confidence=args.min_confidence)
        
        if not candidates:
            if not args.json and not args.benchmark:
                console.print(f"[yellow]Nie udało się zidentyfikować hasha: {hash_str}[/yellow]")
            continue

        best_candidate = candidates[0]
        
        if args.json:
            results_json[hash_str] = candidates
        elif args.hashcat-only:
            print(best_candidate.get("hashcat_mode", "N/A"))
        elif args.cmd:
            print(gen_hashcat_cmd(hash_str, best_candidate))
        elif args.export_hashcat:
            mode = best_candidate.get("hashcat_mode")
            if mode is not None:
                export_lines.append(f"{mode}:{hash_str}")
        elif not args.benchmark:
            pretty_print_results(hash_str, candidates, args.verbose)
    
    if args.benchmark:
        end_time = time.time()
        duration = end_time - start_time
        hashes_per_sec = len(all_hashes) / duration if duration > 0 else float('inf')
        console.print(f"[bold green]Wyniki benchmarku[/bold green]")
        console.print(f"  - Przetworzone hashe: {len(all_hashes)}")
        console.print(f"  - Całkowity czas: {duration:.4f} sekund")
        console.print(f"  - Hashy na sekundę: {hashes_per_sec:.2f}")

    if args.export_hashcat:
        try:
            with open(args.export_hashcat, 'w', encoding='utf-8') as f:
                f.write("\n".join(export_lines) + "\n")
            console.print(f"[bold green]Pomyślnie wyeksportowano {len(export_lines)} hashy do '{args.export_hashcat}'[/bold green]")
        except IOError as e:
            console.print(f"[bold red]Błąd podczas zapisu do pliku eksportu: {e}[/bold red]")
    
    if args.json:
        console.print(json.dumps(results_json, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

