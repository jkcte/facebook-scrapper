#!/usr/bin/env python3
"""
runScript.py

Workflow:
  1) Run facebookScrape.py with a link
  2) Gather *.har files (recursively by default)
  3) For each HAR, run har_extract_fb_serp.py to a temp CSV
  4) Merge all temp CSVs -> final --output CSV (deduplicated)

Usage:
  py runScript.py --link "https://www.facebook.com/..." --output results.csv [--filter "walang pasok"]
"""

import argparse
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

# ---------- Helpers ----------

def pick_python_exe():
    return sys.executable

def file_exists_any(*candidates: str) -> Path | None:
    for c in candidates:
        p = Path(c)
        if p.exists():
            return p
    return None

def run_cmd(cmd_list, cwd=None):
    print("[run]", " ".join(cmd_list))
    return subprocess.run(cmd_list, cwd=cwd, check=False)

def rglob_hars(start_dir: Path, pattern: str = "*.har", only_graphql_name: bool = False):
    """Recursively gather HAR files. If only_graphql_name=True, keep those whose name contains 'graphql' (case-insensitive)."""
    hars = []
    for p in start_dir.rglob(pattern):
        if only_graphql_name:
            if "graphql" in p.name.lower():
                hars.append(p)
        else:
            hars.append(p)
    return sorted(hars)

def merge_csvs(part_csvs: list[Path], merged_out: Path):
    """Merge CSV files with identical headers; deduplicate exact rows."""
    if not part_csvs:
        print("[i] No partial CSVs to merge; nothing to write.")
        return

    # Read headers of the first CSV
    header = None
    seen = set()

    with merged_out.open("w", newline="", encoding="utf-8-sig") as f_out:
        writer = None

        for i, part in enumerate(part_csvs):
            if not part.exists():
                continue
            with part.open("r", encoding="utf-8-sig", newline="") as f_in:
                reader = csv.reader(f_in)
                try:
                    part_header = next(reader)
                except StopIteration:
                    continue  # empty file

                if header is None:
                    header = part_header
                    writer = csv.writer(f_out)
                    writer.writerow(header)
                else:
                    # ensure headers match; if not, try to align or skip
                    if part_header != header:
                        print(f"[!] Header mismatch in {part.name}; skipping this file.")
                        continue

                for row in reader:
                    tup = tuple(row)
                    if tup in seen:
                        continue
                    seen.add(tup)
                    writer.writerow(row)

    print(f"[✓] Merged {len(part_csvs)} CSV(s) → {merged_out.resolve()}")

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(description="Run scraper + interpret HARs into a single CSV.")
    ap.add_argument("--link", required=True, help="Facebook link to scrape (e.g., a profile search URL).")
    ap.add_argument("--output", required=True, help="Output CSV file name (merged results).")
    ap.add_argument("--filter", default=None, help="Optional keyword filter for extracted text (case-insensitive).")
    ap.add_argument("--har-dir", default=".", help="Directory to search for HARs (default: current dir).")
    ap.add_argument("--har-pattern", default="*.har", help="Glob pattern for HAR files (default: *.har).")
    ap.add_argument("--only-graphql-name", action="store_true",
                    help="Only include HAR files whose filename contains 'graphql'.")
    ap.add_argument("--no-recursive", action="store_true", help="Do not search HARs recursively.")
    args = ap.parse_args()

    pyexe = pick_python_exe()

    # Ensure the two required scripts exist
    scrape_script = file_exists_any("facebookScrape.py")
    parser_script = file_exists_any("har_extract_fb_serp.py", "har_extract_fb_texts.py")
    if not scrape_script:
        print("[ERR] facebookScrape.py not found in current directory.")
        sys.exit(1)
    if not parser_script:
        print("[ERR] har_extract_fb_serp.py (or har_extract_fb_texts.py) not found in current directory.")
        sys.exit(1)

    # 1) Run the scraper
    # Try both styles: with --link and positional (in case your scraper expects one or the other)
    print(f"[i] Launching scraper: {scrape_script} with link: {args.link}")
    ret = run_cmd([pyexe, str(scrape_script), "--link", args.link])
    if ret.returncode != 0:
        print("[!] Scraper returned non-zero exit. Trying positional argument style...")
        ret2 = run_cmd([pyexe, str(scrape_script), args.link])
        if ret2.returncode != 0:
            print("[ERR] Scraper failed (both --link and positional). Aborting.")
            sys.exit(1)

    # 2) Find HAR files
    har_root = Path(args.har_dir).resolve()
    print(f"[i] Scanning for HARs under: {har_root}")
    if args.no_recursive:
        hars = sorted([p for p in har_root.glob(args.har_pattern)
                       if not args.only_graphql_name or "graphql" in p.name.lower()])
    else:
        hars = rglob_hars(har_root, args.har_pattern, args.only_graphql_name)

    if not hars:
        print("[ERR] No HAR files found. Check your scraper output or adjust --har-dir / --har-pattern.")
        sys.exit(2)

    print(f"[i] Found {len(hars)} HAR file(s):")
    for p in hars:
        print("   -", p)

    # 3) Run the HAR parser for each HAR into temp CSV parts
    with TemporaryDirectory(prefix="har_parts_") as tmpd:
        tmp_dir = Path(tmpd)
        part_csvs = []

        for i, har in enumerate(hars, start=1):
            part_csv = tmp_dir / f"part_{i:04d}.csv"
            cmd = [pyexe, str(parser_script), str(har), "--out", str(part_csv)]
            if args.filter:
                cmd += ["--filter", args.filter]
            print(f"[i] Parsing HAR {i}/{len(hars)} → {part_csv.name}")
            res = run_cmd(cmd)
            if res.returncode != 0:
                print(f"[!] Parser non-zero exit for {har.name}; skipping.")
                continue
            if part_csv.exists() and part_csv.stat().st_size > 0:
                part_csvs.append(part_csv)
            else:
                print(f"[i] No rows produced for {har.name} (empty part CSV).")

        # 4) Merge parts into final CSV
        out_csv = Path(args.output).resolve()
        merge_csvs(part_csvs, out_csv)

    print("[✓] Done.")

if __name__ == "__main__":
    main()
