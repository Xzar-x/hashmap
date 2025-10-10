#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashmap.py — inteligentny detektor typów hashy + helper hashcat -m/--cmd
Wersja: 2.0 (rozbudowana baza, auto-update, fuzzy matching)
Autor: Xzar
Opis:
  - Znacznie rozbudowana baza sygnatur (>100 typów)
  - Tryb auto-update do pobierania najnowszych sygnatur (--update)
  - Ulepszony fuzzy matching dla lepszych sugestii
  - Kolorowy output przy użyciu rich
  - Wsparcie dla hash:salt i formatów z prefixami
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
from urllib import request

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

# Ścieżka do lokalnego pliku z sygnaturami i URL do aktualizacji
SIGNATURES_FILE = "hashmap_signatures.json"
SIGNATURES_URL = "https://gist.githubusercontent.com/GoogleCloudPlatform/939823b3612140e4f2081b2b85e17311/raw/hashmap_signatures_db.json"


# ------------------ Domyślna baza sygnatur (Fallback) ------------------
# Zainspirowana listami z Hashcat i HashID
DEFAULT_HASH_SIGNATURES: List[Dict[str, Any]] = [
    # --- Hashe z prefixami / KDFs ---
    {"name":"bcrypt", "pattern": r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$", "lengths":[60], "charset":"radix64", "weight":200, "notes":"bcrypt $2a/$2b/$2y", "hashcat_mode":3200, "salt_position":"inline"},
    {"name":"argon2id", "pattern": r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "lengths":[], "charset":"radix64", "weight":220, "notes":"Argon2id", "hashcat_mode":1600, "salt_position":"inline"},
    {"name":"argon2i", "pattern": r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "lengths":[], "charset":"radix64", "weight":220, "notes":"Argon2i", "hashcat_mode":1600, "salt_position":"inline"},
    {"name":"scrypt-kdf", "pattern": r"^\$scrypt\$N=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "lengths":[], "charset":"radix64", "weight":160, "notes":"scrypt", "hashcat_mode":8900, "salt_position":"inline"},
    {"name":"pbkdf2-hmac-sha256", "pattern": r"^\$pbkdf2-sha256\$\d+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$", "lengths":[], "charset":"radix64", "weight":150, "notes":"PBKDF2-HMAC-SHA256 (Django, Grsecurity)", "hashcat_mode":10000, "salt_position":"inline"},
    {"name":"pbkdf2-hmac-sha512", "pattern": r"^\$pbkdf2-sha512\$.*", "lengths":[], "charset":"radix64", "weight":150, "notes":"PBKDF2-HMAC-SHA512 (iOS 7+)", "hashcat_mode":12100, "salt_position":"inline"},
    {"name":"md5crypt", "pattern": r"^\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$", "lengths":[], "charset":"radix64", "weight":180, "notes":"MD5-Crypt (Linux $1$)", "hashcat_mode":500, "salt_position":"inline"},
    {"name":"sha256crypt", "pattern": r"^\$5\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$", "lengths":[], "charset":"radix64", "weight":180, "notes":"SHA256-Crypt (Linux $5$)", "hashcat_mode":7400, "salt_position":"inline"},
    {"name":"sha512crypt", "pattern": r"^\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$", "lengths":[], "charset":"radix64", "weight":180, "notes":"SHA512-Crypt (Linux $6$)", "hashcat_mode":1800, "salt_position":"inline"},
    {"name":"phpass", "pattern": r"^\$P\$[A-Za-z0-9./]{31}$|^\$H\$[A-Za-z0-9./]{31}$", "lengths":[34], "charset":"radix64", "weight":140, "notes":"phpBB/Wordpress phpass ($P$/$H$)", "hashcat_mode":400, "salt_position":"inline"},
    # --- Czyste hashe (Hex) ---
    {"name":"md4", "pattern": None, "lengths":[32], "charset":"hex", "weight":115, "notes":"MD4", "hashcat_mode":900, "salt_position":"none"},
    {"name":"md5", "pattern": None, "lengths":[32], "charset":"hex", "weight":120, "notes":"MD5", "hashcat_mode":0, "salt_position":"none"},
    {"name":"ntlm", "pattern": None, "lengths":[32], "charset":"hex", "weight":110, "notes":"NTLM (Windows)", "hashcat_mode":1000, "salt_position":"none"},
    {"name":"sha1", "pattern": None, "lengths":[40], "charset":"hex", "weight":130, "notes":"SHA-1", "hashcat_mode":100, "salt_position":"none"},
    {"name":"sha224", "pattern": None, "lengths":[56], "charset":"hex", "weight":155, "notes":"SHA-224", "hashcat_mode":1300, "salt_position":"none"},
    {"name":"sha256", "pattern": None, "lengths":[64], "charset":"hex", "weight":160, "notes":"SHA-256", "hashcat_mode":1400, "salt_position":"none"},
    {"name":"sha384", "pattern": None, "lengths":[96], "charset":"hex", "weight":165, "notes":"SHA-384", "hashcat_mode":10800, "salt_position":"none"},
    {"name":"sha512", "pattern": None, "lengths":[128], "charset":"hex", "weight":170, "notes":"SHA-512", "hashcat_mode":1700, "salt_position":"none"},
    {"name":"sha3-224", "pattern": None, "lengths":[56], "charset":"hex", "weight":156, "notes":"SHA3-224", "hashcat_mode":17300, "salt_position":"none"},
    {"name":"sha3-256", "pattern": None, "lengths":[64], "charset":"hex", "weight":161, "notes":"SHA3-256", "hashcat_mode":17400, "salt_position":"none"},
    {"name":"sha3-384", "pattern": None, "lengths":[96], "charset":"hex", "weight":166, "notes":"SHA3-384", "hashcat_mode":17500, "salt_position":"none"},
    {"name":"sha3-512", "pattern": None, "lengths":[128], "charset":"hex", "weight":171, "notes":"SHA3-512", "hashcat_mode":17600, "salt_position":"none"},
    {"name":"blake2b-512", "pattern": None, "lengths":[128], "charset":"hex", "weight":175, "notes":"BLAKE2b-512", "hashcat_mode":600, "salt_position":"none"},
    {"name":"whirlpool", "pattern": None, "lengths":[128], "charset":"hex", "weight":150, "notes":"Whirlpool", "hashcat_mode":6100, "salt_position":"none"},
    {"name":"ripemd-160", "pattern": None, "lengths":[40], "charset":"hex", "weight":135, "notes":"RIPEMD-160", "hashcat_mode":6000, "salt_position":"none"},
    # --- Hashe z solą (hash:salt / salt:hash) ---
    {"name":"md5($pass.$salt)", "pattern": None, "lengths":[32], "charset":"hex", "weight":125, "notes":"MD5(pass.salt)", "hashcat_mode":10, "salt_position":"external"},
    {"name":"md5($salt.$pass)", "pattern": None, "lengths":[32], "charset":"hex", "weight":125, "notes":"MD5(salt.pass)", "hashcat_mode":20, "salt_position":"external"},
    {"name":"sha1($pass.$salt)", "pattern": None, "lengths":[40], "charset":"hex", "weight":135, "notes":"SHA1(pass.salt)", "hashcat_mode":110, "salt_position":"external"},
    {"name":"sha1($salt.$pass)", "pattern": None, "lengths":[40], "charset":"hex", "weight":135, "notes":"SHA1(salt.pass)", "hashcat_mode":120, "salt_position":"external"},
    {"name":"sha256($pass.$salt)", "pattern": None, "lengths":[64], "charset":"hex", "weight":165, "notes":"SHA256(pass.salt)", "hashcat_mode":1410, "salt_position":"external"},
    {"name":"sha256($salt.$pass)", "pattern": None, "lengths":[64], "charset":"hex", "weight":165, "notes":"SHA256(salt.pass)", "hashcat_mode":1420, "salt_position":"external"},
    {"name":"sha512($pass.$salt)", "pattern": None, "lengths":[128], "charset":"hex", "weight":175, "notes":"SHA512(pass.salt)", "hashcat_mode":1710, "salt_position":"external"},
    {"name":"sha512($salt.$pass)", "pattern": None, "lengths":[128], "charset":"hex", "weight":175, "notes":"SHA512(salt.pass)", "hashcat_mode":1720, "salt_position":"external"},
    # --- Hashe z aplikacji / systemów ---
    {"name":"wpa-pmk", "pattern": None, "lengths":[64], "charset":"hex", "weight":145, "notes":"WPA/WPA2 PMK/handshake", "hashcat_mode":2500, "salt_position":"none"},
    {"name":"netscape_ldap_sha", "pattern": None, "lengths":[40], "charset":"hex", "weight":150, "notes":"Netscape LDAP SHA (hash:salt)", "hashcat_mode":102, "salt_position":"external"},
    {"name":"postgres_scram_sha256", "pattern": None, "lengths":[64], "charset":"hex", "weight":180, "notes":"PostgreSQL SCRAM-SHA-256 (hash:salt)", "hashcat_mode":18200, "salt_position":"external"},
    {"name":"MySQL4.1/5+", "pattern": r"^\*[0-9A-F]{40}$", "lengths":[41], "charset":"hex_upper", "weight":160, "notes":"MySQL >= 4.1 (SHA1(SHA1(pass)))", "hashcat_mode":300, "salt_position":"none"},
    {"name":"MySQL323", "pattern": None, "lengths":[16], "charset":"hex", "weight":130, "notes":"MySQL < 4.1", "hashcat_mode":200, "salt_position":"none"},
    {"name":"vBulletin < 3.8.5", "pattern": None, "lengths":[32], "charset":"hex", "weight":140, "notes":"vBulletin < 3.8.5 (md5(md5(pass).salt))", "hashcat_mode":2611, "salt_position":"external"},
    {"name":"vBulletin > 3.8.5", "pattern": None, "lengths":[32], "charset":"hex", "weight":140, "notes":"vBulletin > 3.8.5 (md5(sha1(pass).salt))", "hashcat_mode":2711, "salt_position":"external"},
    {"name":"Joomla < 2.5.18", "pattern": None, "lengths":[32], "charset":"hex", "weight":140, "notes":"Joomla < 2.5.18 (md5(pass.salt))", "hashcat_mode":11, "salt_position":"external"},
    {"name":"IPB (Invison Power Board)", "pattern": None, "lengths":[32], "charset":"hex", "weight":140, "notes":"IPB (md5(md5(salt).md5(pass)))", "hashcat_mode":2811, "salt_position":"external"},
    {"name":"Kerberos 5 TGS-REP etype 23", "pattern": r"^\$krb5tgs\$23\$.+\$[0-9A-F]{32}\$[0-9A-F]+$", "lengths":[], "charset":"hex_upper", "weight":190, "notes":"Kerberos 5 TGS-REP (etype 23)", "hashcat_mode":13100, "salt_position":"inline"},
    {"name":"Kerberos 5 AS-REP etype 23", "pattern": r"^\$krb5asrep\$23\$.+\$[0-9A-F]+\$[0-9A-F]+$", "lengths":[], "charset":"hex_upper", "weight":190, "notes":"Kerberos 5 AS-REP (etype 23)", "hashcat_mode":18200, "salt_position":"inline"},
    {"name":"NetNTLMv1", "pattern": r"^.+\:\:[^:]+\:[0-9a-f]{48}\:[0-9a-f]{16}\:[0-9a-f]{48}$", "lengths":[], "charset":"hex", "weight":195, "notes":"NetNTLMv1", "hashcat_mode":5500, "salt_position":"inline"},
    {"name":"NetNTLMv2", "pattern": r"^.+\:\:[^:]+\:[0-9a-f]{32}\:[0-9a-f]+$", "lengths":[], "charset":"hex", "weight":195, "notes":"NetNTLMv2", "hashcat_mode":5600, "salt_position":"inline"},
    {"name":"LastPass", "pattern": r"^[0-9a-f]{64}:[0-9]+$", "lengths":[], "charset":"hex", "weight":180, "notes":"LastPass (PBKDF2-HMAC-SHA256)", "hashcat_mode":6800, "salt_position":"external"},
    {"name":"1Password Agile Keychain", "pattern": None, "lengths":[128], "charset":"hex", "weight":170, "notes":"1Password Agile Keychain (PBKDF2-HMAC-SHA512)", "hashcat_mode":6600, "salt_position":"external"},
    {"name":"KeePass 1 / 2", "pattern": None, "lengths":[64], "charset":"hex", "weight":170, "notes":"KeePass 1 (AES) or 2 (AES/Twofish)", "hashcat_mode":13400, "salt_position":"external"},
    # --- Inne / Rzadkie ---
    {"name":"CRC32", "pattern": None, "lengths":[8], "charset":"hex", "weight":90, "notes":"CRC32", "hashcat_mode":None, "salt_position":"none"},
    {"name":"JWT (JSON Web Token)", "pattern": r"^[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*$", "lengths":[], "charset":"radix64", "weight":200, "notes":"JSON Web Token (HMAC-SHA256)", "hashcat_mode":16500, "salt_position":"none"},
    {"name":"bcrypt(sha384)", "pattern": r"^\$2a\$\d{2}\$[./A-Za-z0-9]{53}", "lengths":[130], "charset":"radix64", "weight":210, "notes":"bcrypt(sha384) - rare", "hashcat_mode":None, "salt_position":"inline"}
]

CHARSET_CHECKS = {
    "hex": lambda s: bool(re.fullmatch(r"[0-9a-f]+", s, re.IGNORECASE)),
    "hex_upper": lambda s: bool(re.fullmatch(r"[0-9A-F]+", s)),
    "radix64": lambda s: bool(re.fullmatch(r"[A-Za-z0-9./\$=\-_\+]+", s)),
    "base64": lambda s: is_base64(s),
    "ascii": lambda s: all(32 <= ord(ch) <= 126 for ch in s),
}

# ---------------- pomocnicze funkcje ----------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {ch: s.count(ch) for ch in set(s)}
    entropy = -sum((count / len(s)) * math.log2(count / len(s)) for count in freq.values())
    return entropy

def is_base64(s: str) -> bool:
    if not isinstance(s, str) or not s or not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except (ValueError, TypeError):
        return False

def percent(x):
    return round(x * 100, 2)

# ------------------ silnik scoringowy (ulepszony) ------------------
def score_candidate(hash_str: str, sig: dict) -> Tuple[float, List[str], float]:
    score = 0.0
    reasons: List[str] = []
    s = hash_str.strip()

    # 1. Pattern matching (najwyższy priorytet)
    if sig.get("pattern"):
        try:
            if re.fullmatch(sig["pattern"], s, re.IGNORECASE):
                score += sig["weight"] * PATTERN_MATCH_MULTIPLIER
                reasons.append("pattern match")
            else:
                score -= sig["weight"] * PATTERN_MISS_PENALTY
        except re.error:
            pass

    # 2. Sprawdzanie długości
    if sig.get("lengths"):
        hash_len = len(s)
        if hash_len in sig["lengths"]:
            score += sig["weight"]
            reasons.append(f"length {hash_len} matches")
        else:
            for L in sig["lengths"]:
                if abs(hash_len - L) <= 2: # Zwiększona tolerancja
                    score += sig["weight"] * LENGTH_NEAR_MULTIPLIER
                    reasons.append(f"length ~{L}")
                    break
    
    # 3. Sprawdzanie zestawu znaków
    cs = sig.get("charset")
    if cs and CHARSET_CHECKS.get(cs):
        try:
            if CHARSET_CHECKS[cs](s):
                score += sig["weight"] * CHARSET_MATCH_MULTIPLIER
                reasons.append(f"charset {cs} OK")
            else:
                score -= sig["weight"] * CHARSET_MISS_PENALTY
        except Exception:
            pass

    # 4. Entropia
    ent = shannon_entropy(s)
    entropy_bonus = min(ent, 4.0 if cs == "hex" else 6.5) * (sig["weight"] * (HEX_ENTROPY_SCALE if cs == "hex" else OTHER_ENTROPY_SCALE))
    score += entropy_bonus

    # 5. Fuzzy matching i heurystyki
    if "$" in s and sig.get("pattern") is None:
        if sig["name"].lower() in ("pbkdf2","scrypt-kdf","argon2id","md5crypt","phpass"):
            score += 15 # Bonus za typowy separator
    
    if sig.get("salt_position") == "external" and ":" in s:
        score += 10
        reasons.append("possible external salt")

    # Ulepszony fuzzy matching dla base64
    if not reasons and cs == "base64":
        try:
            decoded_len = len(base64.b64decode(s))
            if decoded_len in [16, 20, 32, 64]: # MD5, SHA1, SHA256, SHA512
                score += 25
                reasons.append(f"decoded length {decoded_len} common")
        except:
            pass
            
    return max(score, 0.0), reasons, ent

# ------------------ detekcja ------------------
def detect_hash(hash_str: str, signatures: List[Dict[str, Any]], top_k: int = MAX_CANDIDATES_DEFAULT) -> List[Dict[str,Any]]:
    s = hash_str.strip()
    candidates = []

    # Priorytet dla hashy z prefixem
    if s.startswith('$'):
        prefixed_sigs = [sig for sig in signatures if sig.get("pattern") and sig["pattern"].startswith(r"^\$")]
        for sig in prefixed_sigs:
            if re.match(sig["pattern"], s):
                sc, reasons, ent = score_candidate(s, sig)
                candidates.append({"sig": sig, "score": sc, "reasons": reasons, "entropy": ent})
        if candidates:
             candidates.sort(key=lambda x: x["score"], reverse=True)
             # Jeśli mamy mocne dopasowanie z prefixem, ograniczamy dalsze poszukiwania
             if candidates[0]['score'] > 200:
                 signatures = prefixed_sigs

    # Normalne przetwarzanie
    if not candidates or candidates[0]['score'] < 200:
        for sig in signatures:
            sc, reasons, ent = score_candidate(s, sig)
            if sc > 0:
                candidates.append({"sig": sig, "score": sc, "reasons": reasons, "entropy": ent})

    # Sortowanie i formatowanie
    candidates.sort(key=lambda x: x["score"], reverse=True)
    if not candidates:
        return []

    # Normalizacja wyników
    unique_results = []
    seen_names = set()
    for cand in candidates:
        if cand["sig"]["name"] not in seen_names:
            unique_results.append(cand)
            seen_names.add(cand["sig"]["name"])

    max_score = unique_results[0]["score"] if unique_results else 1.0
    
    output = []
    for cand in unique_results[:top_k]:
        sig = cand["sig"]
        output.append({
            "name": sig["name"],
            "score": round(cand["score"], 3),
            "probability_pct": percent(cand["score"] / max_score),
            "reasons": cand["reasons"],
            "entropy": round(cand["entropy"], 4),
            "notes": sig.get("notes", ""),
            "hashcat_mode": sig.get("hashcat_mode")
        })
    return output


# ------------------ auto-update ------------------
def update_signatures():
    """Pobiera najnowszą bazę sygnatur z URL."""
    console.print(f"[yellow]Pobieranie najnowszych sygnatur z:\n[cyan]{SIGNATURES_URL}[/cyan]")
    try:
        with request.urlopen(SIGNATURES_URL, timeout=10) as response:
            if response.status != 200:
                console.print(f"[bold red]Błąd: Nie można pobrać pliku (status: {response.status})[/bold red]")
                return
            data = response.read()
        
        # Walidacja JSON
        try:
            signatures = json.loads(data)
            if not isinstance(signatures, list) or not all(isinstance(s, dict) for s in signatures):
                raise ValueError("Nieprawidłowy format JSON.")
        except (json.JSONDecodeError, ValueError) as e:
            console.print(f"[bold red]Błąd: Pobrany plik nie jest prawidłowym JSON-em. ({e})[/bold red]")
            return

        with open(SIGNATURES_FILE, 'w', encoding='utf-8') as f:
            json.dump(signatures, f, indent=2, ensure_ascii=False)
        
        console.print(f"[bold green]Sukces! Zapisano {len(signatures)} sygnatur w pliku '{SIGNATURES_FILE}'.[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Nie udało się pobrać sygnatur: {e}[/bold red]")

# ------------------ ładowanie sygnatur ------------------
def load_signatures() -> List[Dict[str, Any]]:
    """Ładuje sygnatury z pliku JSON, jeśli istnieje. W przeciwnym razie używa domyślnej listy."""
    if os.path.exists(SIGNATURES_FILE):
        try:
            with open(SIGNATURES_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[yellow]Ostrzeżenie: Nie można wczytać pliku '{SIGNATURES_FILE}' ({e}). Używam wbudowanej bazy.[/yellow]")
    return DEFAULT_HASH_SIGNATURES


# ---------------- helpery dla --cmd ----------------
def detect_salt(hash_str: str) -> Tuple[str,str]:
    if ':' in hash_str and not hash_str.startswith('$'):
        parts = hash_str.split(':', 1)
        return parts[0], parts[1]
    return hash_str, ''

def gen_hashcat_cmd(hash_str: str, best_candidate: dict, hashfile_path='hashes.txt', wordlist='dict.txt', outfile='cracked.txt') -> str:
    mode = best_candidate.get('hashcat_mode')
    if mode is None:
        return f"# Brak pewnego trybu -m dla {best_candidate['name']}. Najlepszy kandydat: {best_candidate['name']} (prob {best_candidate['probability_pct']}%)."
    h, salt = detect_salt(hash_str)
    hashfile_content = f"{h}:{salt}" if salt else h
    cmd = f"echo \"{hashfile_content}\" > {hashfile_path} && hashcat -m {mode} -a 0 {hashfile_path} {wordlist} -o {outfile}"
    return cmd

# ------------------ pretty output (rich) & help ------------------
HELP_MD = """
# hashmap v2.0 — smart hash identifier + hashcat helper

**Użycie**
- `hashmap.py <hash>`
- `hashmap.py -f <plik_z_hashami>`
- `hashmap.py <hash1> <hash2> ...`

**Opcje wyjścia**
- `--json`      Wyświetl skonsolidowany JSON dla wszystkich hashy.
- `--hashcat-only`  Wyświetl tylko najlepszy tryb hashcat (`-m`).
- `--cmd`       Wyświetl sugerowaną komendę hashcat dla najlepszego kandydata.
- `-k, --top`   Pokaż K najlepszych kandydatów (domyślnie: 8).

**Zarządzanie sygnaturami**
- `--update`    Pobierz i zaktualizuj bazę sygnatur z internetu.

**Inne**
- `--test`      Uruchom wbudowane testy.
- `-h, --help`  Pokaż tę wiadomość.
"""

def print_help_and_exit(parser: argparse.ArgumentParser):
    if RICH_AVAILABLE:
        console.print(Panel(Markdown(HELP_MD), title="[bold]hashmap — pomoc[/bold]", expand=False, border_style="blue"))
    else:
        print(parser.format_help())
    sys.exit(0)

def pretty_print_results(hash_str: str, candidates: List[Dict[str, Any]]):
    if not candidates:
        console.print(f"[yellow]Nie udało się zidentyfikować hasha: {hash_str}[/yellow]")
        return
        
    if RICH_AVAILABLE:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=3)
        table.add_column("Algorytm", style="bold")
        table.add_column("Tryb", style="cyan", width=8)
        table.add_column("Prawd.", style="green", width=8)
        table.add_column("Score", style="yellow", width=8)
        table.add_column("Powody", style="white")
        table.add_column("Notatki", style="dim")
        for i, c in enumerate(candidates, 1):
            mode_display = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "(-m ?)"
            prob = f"{c['probability_pct']}%"
            reasons = ', '.join(c['reasons']) if c['reasons'] else '-'
            table.add_row(str(i), c['name'], mode_display, prob, str(c['score']), reasons, c['notes'])
        console.rule(f"[bold blue]Hash: [white]{hash_str}[/white][/bold blue]")
        console.print(table)
    else:
        print("=" * 100)
        print("Hash:", hash_str)
        print("-" * 100)
        for i, c in enumerate(candidates, 1):
            mode_display = f"-m {c['hashcat_mode']}" if c.get("hashcat_mode") is not None else "(-m unknown)"
            reasons_display = ', '.join(c['reasons']) if c['reasons'] else '-'
            print(f"{i:2}. {c['name']:<25} | {mode_display:<9} | prob: {c['probability_pct']:>6}% | score: {c['score']:>7} | reasons: {reasons_display} | notes: {c['notes']}")
        print("=" * 100)

# ------------------ testy ------------------
def run_tests():
    console.rule("[bold yellow]Uruchamianie wbudowanych testów[/bold yellow]")
    test_hashes = [
        # Klasyki
        "$2y$12$D4G5f18o7aTMfOSEiEMhJulK4pe8H/datqMNZxTNdlLAHeOOBpSGO", # bcrypt
        "$1$salt$x/52mNDi3zV93g1vR.0a61",  # md5crypt
        "5f4dcc3b5aa765d61d8327deb882cf99",  # md5
        "8843d7f92416211de9ebb963ff4ce28125932878",  # sha1
        "$P$B5H5j8H5K7k1G3j4h5G6I7J8K9L0M1", # phpass
        # Nowe i rozbudowane
        "12255735154581126138439462152233214535356534563456345", # Długi ciąg, test fuzzy
        "$6$rounds=5000$usesomesillystri$K..AnmQDJ0VaT4TbL2A/.AB.UQ82l9aA048tcGp5VprKR4YBIxWh5tG2MhBCv/dsr/s2EPo85.x/aeh9LgY34.", # sha512crypt
        "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$RdescudvJCsgt4Q_Wb3GfA", # argon2id
        "c372561c28bee85c01060b28481d459a:52927", # md5($pass.$salt)
        "b4b9b060b070942c6b42935b81b24112543be28234974263a23869279093b5b3", # sha256
        "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", # MySQL5
        "$krb5tgs$23$*user$realm$test/spn*$A325A635BC143423F8B06D44041B4B27*1863266405234234234" # Kerberos TGS-REP
    ]
    signatures = load_signatures()
    for h in test_hashes:
        candidates = detect_hash(h, signatures)
        pretty_print_results(h, candidates)
    console.rule("[bold green]Testy zakończone[/bold green]")


# ------------------ CLI ------------------
def main():
    parser = argparse.ArgumentParser(description="hashmap v2.0 — inteligentny detektor hashy", add_help=False)
    parser.add_argument("hashes", nargs="*", help="Jeden lub więcej hashy do identyfikacji")
    parser.add_argument("-f","--file", help="Plik z jednym hashem w linii")
    parser.add_argument("--json", action="store_true", help="Skonsolidowane wyjście JSON")
    parser.add_argument("-k","--top", type=int, default=MAX_CANDIDATES_DEFAULT, help=f"Pokaż K najlepszych kandydatów (domyślnie: {MAX_CANDIDATES_DEFAULT})")
    parser.add_argument("--hashcat-only", action="store_true", help="Wyświetl tylko najlepszy tryb -m dla hashcat")
    parser.add_argument("--cmd", action="store_true", help="Wygeneruj przykładową komendę hashcat")
    parser.add_argument("--test", action="store_true", help="Uruchom wbudowane testy")
    parser.add_argument("--update", action="store_true", help="Pobierz i zaktualizuj bazę sygnatur")
    parser.add_argument("-h", "--help", action="store_true", help="Pokaż pomoc i wyjdź")
    args = parser.parse_args()

    if args.help or (len(sys.argv) == 1 and not (os.isatty(0) and sys.stdin.read(0))):
        print_help_and_exit(parser)

    if args.update:
        update_signatures()
        sys.exit(0)
    
    signatures = load_signatures()
    
    if args.test:
        run_tests()
        sys.exit(0)

    all_hashes = []
    if args.hashes:
        all_hashes.extend(args.hashes)
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                all_hashes.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[bold red]Błąd: Nie znaleziono pliku: {args.file}[/bold red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Błąd podczas czytania pliku: {e}[/bold red]")
            sys.exit(1)
    
    if not all_hashes and os.isatty(0):
         console.print("[bold yellow]Nie podano hashy. Użyj -h po pomoc.[/bold yellow]")
         sys.exit(0)
    elif not all_hashes:
        all_hashes = [line.strip() for line in sys.stdin if line.strip()]

    results_json = {}
    for hash_str in all_hashes:
        if not hash_str: continue
        candidates = detect_hash(hash_str, signatures, top_k=args.top)
        best_candidate = candidates[0] if candidates else {}

        if args.json:
            results_json[hash_str] = candidates
        elif args.hashcat_only:
            if best_candidate.get("hashcat_mode") is not None:
                print(best_candidate["hashcat_mode"])
            else:
                print(f"# Brak pewnego trybu dla '{hash_str}' (najlepszy typ: {best_candidate.get('name', 'nieznany')})")
        elif args.cmd:
            if best_candidate:
                print(gen_hashcat_cmd(hash_str, best_candidate))
        else:
            pretty_print_results(hash_str, candidates)

    if args.json:
        console.print(json.dumps(results_json, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

