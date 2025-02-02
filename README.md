# HashChecker

🔍 Hash Checker
Hash Checker is a command-line utility for verifying file integrity and identifying hash types. It supports multiple hashing algorithms, allowing users to calculate and compare hashes efficiently.

Features
📂 File Integrity Check – Compute and verify file hashes to detect modifications.
🔎 Hash Identification – Determine the type of a given hash (MD5, SHA-1, SHA-256, or SHA-512).
⚡ Fast & Lightweight – Minimal dependencies and quick execution.
Usage
Identify a Hash Type:
sh
Copy
Edit
python hash_checker.py --hash d2d2d0d2d3d3d4d4e5e5e6e6e7e7e8e8
Output: Identified hash type: SHA-256

Verify File Integrity:
sh
Copy
Edit
python hash_checker.py path/to/file --hash expected_hash --algo sha256
Output: ✅ Hash matches! File integrity verified.

Requirements
Python 3.x
Installation
Clone the repository and run:

sh
Copy
Edit
git clone https://github.com/yourusername/hash-checker.git
cd hash-checker
python hash_checker.py --help
License
This project is licensed under the MIT License.
