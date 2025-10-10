hashmap.py 🗺️ - Smart Hash Identifier & Hashcat Helper

https://img.shields.io/badge/python-3.6+-blue.svg
https://img.shields.io/badge/license-MIT-green.svg
https://img.shields.io/badge/features-70+_hash_types-orange.svg

Advanced hash type detection with intelligent scoring system and hashcat integration

---

🚀 Quick Overview

hashmap.py is a sophisticated hash identification tool that goes beyond simple pattern matching. It uses a multi-factor scoring system to accurately identify 70+ hash types and provides seamless integration with hashcat for password cracking.

```bash
# Basic usage
python hashmap.py "5f4dcc3b5aa765d61d8327deb882cf99"

# Result: Identifies as MD5 with 98% confidence
```

---

✨ Features

🔍 Advanced Detection Engine

· Multi-factor scoring: Pattern matching, length analysis, charset validation, and heuristics
· 70+ hash types: From common MD5/SHA to advanced KDFs like Argon2 and bcrypt
· Smart confidence scoring: Probability-based rankings instead of binary matches

🛠️ Hashcat Integration

· Direct mode export: --hashcat-only outputs just the hashcat mode
· Command generation: --cmd creates ready-to-use hashcat commands
· Batch export: --export-hashcat creates hashcat-compatible files

📊 Professional Output

· Rich terminal support: Beautiful tables with colors and formatting
· Verbose mode: See detailed scoring breakdown for each candidate
· JSON export: Machine-readable output for automation
· Fallback support: Works on any terminal without rich library

🔄 Maintenance & Updates

· Auto-update system: Download latest hash signatures with --update
· Rate limiting: Prevents excessive update requests (1-hour cooldown)
· Validation: Verifies signature integrity before applying updates

⚡ Performance & Testing

· Benchmark mode: Measure processing speed for large hash lists
· Built-in tests: Comprehensive test vectors to verify detection accuracy
· Stream processing: Handle stdin, files, and command-line arguments

---

🏆 Comparison with Other Tools

Feature hashmap.py hashid Haiti hashpy
Scoring System ✅ Multi-factor ❌ Basic ❌ Basic ⚠️ Limited
Hash Types ✅ 70+ ✅ 200+ ✅ 200+ ⚠️ ~50
Hashcat Integration ✅ Excellent ⚠️ Basic ✅ Good ⚠️ Basic
Confidence Levels ✅ Percentage-based ❌ Binary ❌ Binary ⚠️ Limited
Auto-Update ✅ Yes ❌ No ❌ No ❌ No
Verbose Analysis ✅ Detailed ❌ No ❌ No ❌ No
Export Options ✅ Multiple ❌ No ⚠️ Limited ❌ No

Why hashmap.py is superior:

· 🎯 Smarter detection with weighted scoring instead of simple pattern matching
· 📈 Confidence metrics help you judge result reliability
· 🔧 Better hashcat integration with command generation and batch export
· 🚀 Active maintenance with update system and comprehensive testing
· 💡 Transparent process with verbose mode showing exactly how decisions are made

---

🛠️ Installation

Basic Installation

```bash
git clone https://github.com/yourusername/hashmap.git
cd hashmap
```

Optional: Install Rich for Enhanced Display

```bash
pip install rich
```

Note: hashmap works perfectly without rich - it automatically falls back to basic terminal output.

---

📖 Usage Examples

🔍 Basic Hash Identification

```bash
python hashmap.py "5f4dcc3b5aa765d61d8327deb882cf99"
python hashmap.py "$2y$12$D4G5f18o7aTMfOSEiEMhJulK4pe8H/datqMNZxTNdlLAHeOOBpSGO"
```

📁 Processing Multiple Hashes

```bash
# From file
python hashmap.py -f hashes.txt

# From stdin
cat hashes.txt | python hashmap.py

# Multiple arguments
python hashmap.py "hash1" "hash2" "hash3"
```

🔧 Advanced Options

```bash
# Show scoring details
python hashmap.py -v "5f4dcc3b5aa765d61d8327deb882cf99"

# Get only hashcat mode
python hashmap.py --hashcat-only "5f4dcc3b5aa765d61d8327deb882cf99"

# Generate hashcat command
python hashmap.py --cmd "5f4dcc3b5aa765d61d8327deb882cf99"

# Export to hashcat format
python hashmap.py --export-hashcat output.hc "5f4dcc3b5aa765d61d8327deb882cf99"

# JSON output for automation
python hashmap.py --json "5f4dcc3b5aa765d61d8327deb882cf99"
```

🧪 Testing & Maintenance

```bash
# Run built-in tests
python hashmap.py --test

# Update hash signatures
python hashmap.py --update

# Benchmark performance
python hashmap.py --benchmark -f large_hashes.txt
```

---

🎯 Detection Capabilities

Supported Hash Categories

· 🔐 KDF Hashes: bcrypt, Argon2, scrypt, PBKDF2
· 📦 Common Hashes: MD5, SHA1, SHA256, SHA512
· 🏢 System Hashes: NTLM, Kerberos, DCC2, NetNTLMv2
· 📶 Wireless: WPA-PMKID, WPA-EAPOL
· 🌐 Application: Django, phpass, Cisco Type 7/9
· 🧂 Salted Variants: MD5/SHA1 with various salt positions

Smart Detection Features

· Pattern Recognition: Regex matching for structured hashes
· Length Analysis: Exact and near-length matching
· Charset Validation: Hex, Base64, Radix64, ASCII
· Heuristic Bonuses: Context-aware scoring adjustments
· Confidence Scoring: Percentage-based reliability metrics

---

📊 Sample Output

Standard Detection

```
┌ Analysis for: 5f4dcc3b5aa765d61d8327deb882cf99 ┐
┌───┬──────────────┬─────────┬───────┬─────────────────────────────┬────────────────────┐
│ # │ Algorithm    │ Mode    │ Prob. │ Scoring Details             │ Notes              │
├───┼──────────────┼─────────┼───────┼─────────────────────────────┼────────────────────┤
│ 1 │ md5          │ -m 0    │ 100%  │ Length 32: +120.0, Charset… │ MD5                │
│ 2 │ md4          │ -m 900  │ 95.8% │ Length 32: +115.0, Charset… │ MD4                │
│ 3 │ ntlm         │ -m 1000 │ 91.6% │ Length 32: +110.0, Charset… │ NTLM (Windows)     │
└───┴──────────────┴─────────┴───────┴─────────────────────────────┴────────────────────┘
```

Hashcat Integration

```bash
$ python hashmap.py --cmd "5f4dcc3b5aa765d61d8327deb882cf99"
hashcat -m 0 -a 0 "5f4dcc3b5aa765d61d8327deb882cf99" /path/to/wordlist.txt
```

---

🔧 Technical Details

Scoring Algorithm

The detection uses a sophisticated scoring system:

· Pattern Matching: Major bonus for regex matches
· Length Analysis: Points for exact or near-exact length matches
· Charset Validation: Bonus for valid character sets
· Heuristic Adjustments: Context-aware bonuses/penalties
· Weight System: Different hash types have different base weights

Configuration Options

· --min-confidence: Filter results by probability threshold
· --top: Control number of candidates displayed
· --verbose: See the complete scoring breakdown
· --benchmark: Performance timing for large datasets

---

🤝 Contributing

We welcome contributions! Here's how you can help:

1. Report Bugs: Open an issue with examples and details
2. Suggest Features: Share your ideas for improvements
3. Add Signatures: Contribute new hash type detection patterns
4. Improve Documentation: Help make the tool more accessible

Adding New Hash Types

Edit the DEFAULT_HASH_SIGNATURES list with:

· Pattern regex
· Expected lengths
· Character set
· Hashcat mode
· Weight/priority

---

📜 License

MIT License - feel free to use this tool for both personal and commercial purposes.

---

🐛 Bug Reports & Support

If you encounter any issues:

1. Check the existing issues on GitHub
2. Run with -v flag and include the verbose output
3. Provide example hashes that demonstrate the problem
4. Include your Python version and operating system

---

🎉 Acknowledgments

Credits & Inspiration:

· Based on original work by Xzar
· Enhanced with AI assistance from Gemini
· Inspired by the hashcat community and existing identification tools
· Thanks to all contributors and testers who helped improve detection accuracy

---

⚠️ Legal Disclaimer

This tool is intended for:

· Security research and education
· Authorized penetration testing
· Forensic analysis and incident response
· System administration and maintenance

Always ensure you have proper authorization before testing or attacking any systems.

---

<div align="center">

⭐ If you find this tool useful, please give it a star on GitHub!

</div>

---

