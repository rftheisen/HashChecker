import hashlib
import argparse
import re

def identify_hash(hash_value):
    hash_patterns = {
        "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
        "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
        "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
        "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
    }
    
    for algo, pattern in hash_patterns.items():
        if pattern.fullmatch(hash_value):
            return algo
    return "Unknown hash type"

def calculate_hash(file_path, hash_algorithm):
    hash_func = getattr(hashlib, hash_algorithm)()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

def main():
    parser = argparse.ArgumentParser(description="Command-line file hash checker and identifier.")
    parser.add_argument("file", nargs="?", help="Path to the file to check")
    parser.add_argument("--hash", help="Hash value to identify or verify")
    parser.add_argument("--algo", choices=["md5", "sha1", "sha256", "sha512"], default="sha256", help="Hashing algorithm (default: sha256)")
    args = parser.parse_args()
    
    if args.hash and not args.file:
        hash_type = identify_hash(args.hash)
        print(f"Identified hash type: {hash_type}")
    elif args.file and args.hash:
        computed_hash = calculate_hash(args.file, args.algo)
        if computed_hash:
            print(f"Computed {args.algo} hash: {computed_hash}")
            if computed_hash.lower() == args.hash.lower():
                print("✅ Hash matches! File integrity verified.")
            else:
                print("❌ Hash mismatch! File may be corrupted or altered.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
