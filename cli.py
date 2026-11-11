#!/usr/bin/env python3
"""
Command-line interface, equivalent to the original script.

Usage:
    python cli.py --input ./input --btld btld-000014E0
"""
import argparse
import os
import sys

from l3extract.core import L3Error, extract_l3


def main():
    ap = argparse.ArgumentParser(description="Extract the L3 RSA key for a BTLD.")
    ap.add_argument("--input", default="input",
                    help="folder with the sec_* / bmw_* files (default: ./input)")
    ap.add_argument("--btld", required=True, help="e.g. btld-000014E0")
    ap.add_argument("--out", help="output .py path (default: l3_<btld>.py in cwd)")
    args = ap.parse_args()

    try:
        result = extract_l3(args.input, args.btld, log=lambda m: print(m))
    except L3Error as e:
        sys.exit(f"Error: {e}")

    print("\n" + result.as_python())
    safe = result.btld.replace("btld-", "").replace(".", "_").upper()
    out_path = args.out or f"l3_{safe}.py"
    with open(out_path, "w") as f:
        f.write(result.as_python())
    print(f"Written to {out_path}")


if __name__ == "__main__":
    main()
