#!/usr/bin/env python3
# facebookScrape.py — capture FB network using temporary Playwright profile (Option 2)
from __future__ import annotations

import argparse, csv, os, re, sys, time, shutil
from datetime import datetime
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

GRAPHQL_RE = re.compile(r"https://www\.facebook\.com/api/graphql/", re.I)
ROUTE_RE   = re.compile(r"/ajax/bulk-route-definitions", re.I)

def now_ms() -> int: return int(time.time()*1000)
def ensure_dir(p: Path) -> Path: p.mkdir(parents=True, exist_ok=True); return p

def wait_for_file(path: Path, timeout_s: float = 5.0) -> bool:
    deadline = time.time() + max(0.0, timeout_s)
    while time.time() < deadline:
        try:
            if path.exists() and path.stat().st_size > 0:
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return path.exists() and path.stat().st_size > 0

def main():
    ap = argparse.ArgumentParser(description="Capture FB GraphQL/Route + HAR with temp profile (Option 2).")
    ap.add_argument("--link", required=True, help="Facebook URL to open.")
    ap.add_argument("--har-export", default=None, help="Optional: copy HAR after capture.")
    ap.add_argument("--har-wait-s", type=float, default=5.0)
    ap.add_argument("--scrolls", type=int, default=20)
    ap.add_argument("--initial-buffer-s", type=float, default=10.0)
    ap.add_argument("--per-scroll-s", type=float, default=5.0)
    ap.add_argument("--nav-timeout-s", type=float, default=60.0)
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--session-root", default="debug_graphql_cap")
    ap.add_argument("--har-filename", default="network.har")
    ap.add_argument("--no-har", action="store_true")
    args = ap.parse_args()

    # Temporary Playwright profile path
    user_data_root = Path(r"C:\Users\Owner\Documents\GitHub\facebook-scrapper\pw_profile")
    chrome_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

    print(f"[!] Close all Chrome instances before running.")
    print(f"[i] Using temporary profile: {user_data_root}")

    # Session directories
    ts = now_ms()
    session_dir = ensure_dir(Path(args.session_root)/f"session_{ts}")
    cycle_dir   = ensure_dir(session_dir/"cycle_00")
    manifest_fp = session_dir/"manifest.csv"
    har_path    = session_dir/args.har_filename
    print(f"[i] Session dir: {session_dir.resolve()}")
    print(f"[i] HAR: {'disabled' if args.no_har else har_path.resolve()}")

    with manifest_fp.open("w", newline="", encoding="utf-8-sig") as f:
        csv.writer(f).writerow([
            "when_iso","cycle","scroll_idx","status","size_bytes","friendly_name","doc_id",
            "is_json","is_serp","kind","file_path","url"
        ])

    graphql_seen=route_seen=graphql_saved=route_saved=non_json=0
    current_scroll_idx = -1

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(user_data_root),
            executable_path=chrome_exe,
            channel="chrome",
            headless=args.headless,
            record_har_path=str(har_path) if not args.no_har else None,
            record_har_mode="full"
        )

        try: context.grant_permissions(["notifications"], origin="https://www.facebook.com")
        except Exception: pass

        page = context.pages[0] if context.pages else context.new_page()

        # --- Response handler ---
        def save_blob(prefix, scroll_idx, url, status, body_bytes, kind):
            nonlocal graphql_saved, route_saved, non_json
            out_path = cycle_dir / f"{prefix}_{now_ms()}.json"
            out_path.write_bytes(body_bytes)
            if kind=="GraphQL": graphql_saved += 1
            else: route_saved += 1
            csv.writer(manifest_fp.open("a", newline="", encoding="utf-8-sig")).writerow(
                [datetime.now().isoformat(timespec="seconds"),0,scroll_idx,status,len(body_bytes),
                 "", "", 1, 1 if prefix=="graphql" else 0, kind, str(out_path), url]
            )

        page.on("response", lambda resp: save_blob(
            "graphql" if GRAPHQL_RE.search(resp.url) else "route" if ROUTE_RE.search(resp.url) else "other",
            current_scroll_idx,
            resp.url,
            resp.status,
            resp.body() if not resp.body() is None else b"",
            "GraphQL" if GRAPHQL_RE.search(resp.url) else "Route"
        ))

        # --- Navigate ---
        print(f"[i] Navigating to {args.link}")
        page.goto(args.link, wait_until="domcontentloaded", timeout=int(args.nav_timeout_s*1000))

        print(f"[i] Initial buffer: {args.initial_buffer_s}s")
        time.sleep(args.initial_buffer_s)

        # --- Scroll ---
        try: last_h = page.evaluate("() => document.body.scrollHeight")
        except Exception: last_h = 0

        for i in range(args.scrolls):
            current_scroll_idx = i
            page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
            time.sleep(args.per_scroll_s)
            try: new_h = page.evaluate("() => document.body.scrollHeight")
            except Exception: new_h = last_h
            print(f"[i] scroll {i+1}/{args.scrolls} • height={new_h}")
            if new_h <= last_h: print("[i] No more content; stopping."); break
            last_h = new_h

        print("[i] Final idle: 5s")
        time.sleep(5)
        context.close()

        # --- HAR export ---
        if not args.no_har:
            if wait_for_file(har_path, timeout_s=args.har_wait_s):
                if args.har_export:
                    shutil.copy2(har_path, Path(args.har_export))
                    print(f"[✓] HAR exported to: {Path(args.har_export).resolve()}")
                else:
                    print(f"[✓] HAR saved at: {har_path.resolve()}")
            else:
                print("[!] HAR not found or empty.")

    # --- Debug summary ---
    print("\n=== DEBUG SUMMARY ===")
    print(f"Session dir:   {session_dir.resolve()}")
    print(f"Manifest:      {manifest_fp.resolve()}")
    print(f"GraphQL saved: {graphql_saved}")
    print(f"Route saved:   {route_saved}")

if __name__ == "__main__":
    main()
