<img src="https://raw.githubusercontent.com/Xzar-x/images/main/hashmap.png" alt="hashmap" width="200">

hashmap

Intelligent hash type detector + hashcat helper

> Lightweight, readable Python script that suggests possible hashing algorithms, evaluates match confidence, and generates sample hashcat commands.




---

Key Information

Author: Xzar

Version: 1.6 (final)

Language: Python 3

Purpose: quick hash type identification, hashcat -m mode suggestion, and convenient output (rich table or JSON)



---

Features

Colorful output using rich (with fallback if rich is not installed)

Consolidated JSON output for multiple hashes

Support for hash:salt formats (detects external salts)

Recognizes both encoded formats ($argon2, $2y$, $1$, etc.) and pure hex/base64

Generates sample hashcat commands (--cmd flag)

Built-in test mode (--test) with sample vectors



---

Requirements

Python 3.8+

rich (for colorful output, included in requirements.txt)



---

Installation

1. Clone the repository:



git clone <repo-url>
cd <repo>

2. Create a virtual environment (optional but recommended) and install dependencies via requirements.txt:



python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.\.venv\Scripts\activate  # Windows
pip install -r requirements.txt

3. Make the script executable (optional):



chmod +x hashmap.py


---

Usage

# Simple hash detection
./hashmap.py "5f4dcc3b5aa765d61d8327deb882cf99"

# Multiple hashes as arguments
./hashmap.py hash1 hash2 hash3

# Read hashes from a file (1 hash per line)
./hashmap.py -f hashes.txt

# Output JSON
./hashmap.py -f hashes.txt --json

# Print only the suggested hashcat mode (-m)
./hashmap.py "$2y$12$..." --hashcat-only

# Generate sample hashcat command (echo to file + hashcat)
./hashmap.py --cmd "c372561c28bee85c01060b28481d459a:52927"

# Run built-in tests
./hashmap.py --test


---

Output format

Default: table ranking candidates, probability percentage, reasons, and notes.

--json: returns a JSON object with hashes as keys and candidate lists as values.



---

Commonly supported algorithms / hashcat modes (selected)

bcrypt — -m 3200  (example: $2y$...)

argon2 — complex encoding, some variants may not have a definite -m

md5 — -m 0

ntlm — -m 1000

sha1 — -m 100

sha256 — -m 1400

phpass — -m 400

md5crypt — -m 500


> Note: The script contains a list of signatures and weights (HASH_SIGNATURES) — results are heuristic and should be verified before attack.




---

Example generated command --cmd

The script creates a hashes.txt file with a single entry (hash[:salt]) and suggests a hashcat command:

# example generated command
echo 'c372561c28bee85c01060b28481d459a:52927' > hashes.txt && \
  hashcat -m 0 -a 0 hashes.txt dict.txt -o cracked.txt


---

Tests

The built-in --test mode runs a few control vectors (bcrypt, md5crypt, md5, sha1, ntlm, phpass, hash:salt). Use this after code changes to quickly check for regressions.


---

Contributing

Want to add a new signature, improve scoring, or integrate other tools? Open a pull request. Tips:

Add new signatures to HASH_SIGNATURES with: name, pattern (regex), lengths, charset, weight, notes, hashcat_mode, salt_position.

Add test vectors in the run_tests() function.



---

TODO / Ideas

Expand signature list and add unit tests (pytest).

Integrate with hashcat-utils / maskprocessor for mask generation.

Improve base64 detection and differentiate variants (URL-safe, etc.).

CSV/Excel export for results.



---

License

Default: MIT — add a LICENSE file to explicitly set a license.


---

Contact

Report issues, suggest algorithms, or propose improvements via issues or PRs.

