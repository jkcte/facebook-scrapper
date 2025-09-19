#!/usr/bin/env python3
# facebookScrape.py — capture FB network using your real Chrome/Edge profile
from __future__ import annotations

import argparse, csv, json, os, re, sys, time, shutil
from datetime import datetime
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

IS_WINDOWS = (os.name == "nt")
GRAPHQL_RE = re.compile(r"https://www\.facebook\.com/api/graphql/", re.I)
ROUTE_RE   = re.compile(r"/ajax/bulk-route-definitions", re.I)

def _expand(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))

def detect_default_browser_windows() -> str | None:
    if not IS_WINDOWS: return None
    try:
        import winreg  # type: ignore
        key = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            progid, _ = winreg.QueryValueEx(k, "ProgId")
            progid = (progid or "").lower()
            if "edge" in progid or "appx" in progid: return "edge"
            if "chrome" in progid: return "chrome"
    except Exception:
        pass
    return None

def default_profile_root(browser: str) -> Path | None:
    if not IS_WINDOWS: return None
    local = os.environ.get("LOCALAPPDATA"); roaming = os.environ.get("APPDATA")
    if browser == "chrome" and local:
        p = Path(local)/"Google"/"Chrome"/"User Data"; return p if p.exists() else None
    if browser == "edge" and local:
        p = Path(local)/"Microsoft"/"Edge"/"User Data"; return p if p.exists() else None
    return None

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
    ap = argparse.ArgumentParser(description="Capture FB GraphQL/Route + HAR using real profile.")
    ap.add_argument("--link", required=True, help="Facebook URL to open.")
    ap.add_argument("--har-export", default=None, help="Optional: copy HAR after capture.")
    ap.add_argument("--har-wait-s", type=float, default=5.0)
    ap.add_argument("--scrolls", type=int, default=20)
    ap.add_argument("--initial-buffer-s", type=float, default=10.0)
    ap.add_argument("--per-scroll-s", type=float, default=5.0)
    ap.add_argument("--nav-timeout-s", type=float, default=60.0)
    ap.add_argument("--browser", choices=["auto","chrome","edge"], default="auto")
    ap.add_argument("--profile-root", type=str, default=None, help="User-data dir.")
    ap.add_argument("--profile-name", type=str, default="Default", help="Profile folder name.")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--session-root", default="debug_graphql_cap")
    ap.add_argument("--har-filename", default="network.har")
    ap.add_argument("--no-har", action="store_true")
    args = ap.parse_args()

    # Resolve browser
    b = args.browser
    if b == "auto":
        b = detect_default_browser_windows() or "chrome"
    if b not in ("chrome","edge"):
        print("[ERR] Unsupported browser."); sys.exit(1)

    # Resolve profile root
    user_data_root = Path(_expand(args.profile_root)) if args.profile_root else default_profile_root(b)
    if not user_data_root or not user_data_root.exists():
        print(f"[ERR] Could not locate user-data root for {b}."); sys.exit(1)

    print(f"[!] Close {b.capitalize()} completely before running.")
    print(f"[i] Profile root: {user_data_root}")
    print(f"[i] Profile name: {args.profile_name}")

    # Session setup
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
        # Persistent context
        common_kwargs = dict(
            user_data_dir=str(user_data_root),
            headless=args.headless,
            args=[f"--profile-directory={args.profile_name}"]
        )
        if not args.no_har:
            common_kwargs.update(record_har_path=str(har_path), record_har_mode="full")

        channel = "chrome" if b=="chrome" else "msedge"
        context = p.chromium.launch_persistent_context(channel=channel, **common_kwargs)

        try: context.grant_permissions(["notifications"], origin="https://www.facebook.com")
        except Exception: pass

        page = context.pages[0] if context.pages else context.new_page()

        # --- Response handler ---
        def get_req_meta(resp):
            req = resp.request
            friendly = req.headers.get("x-fb-friendly-name") or ""
            doc_id = ""
            try:
                if req.method.upper()=="POST" and req.post_data:
                    for part in req.post_data.split("&"):
                        if part.startswith("doc_id="): doc_id = part.split("=",1)[1]
                        elif not friendly and part.startswith("fb_api_req_friendly_name="):
                            friendly = part.split("=",1)[1]
            except Exception: pass
            return friendly, doc_id

        def is_search_serp(name: str) -> bool:
            return bool(name and "SearchCometResultsPaginatedResultsQuery" in name)

        def save_blob(prefix, scroll_idx, url, status, body_bytes, friendly, doc_id, is_json, is_serp, kind):
            nonlocal graphql_saved, route_saved, non_json
            ofn = f"{prefix}_{now_ms()}.{'json' if is_json else 'bin'}"
            out_path = cycle_dir / ofn
            out_path.write_bytes(body_bytes)
            if is_json:
                print(f"[✓] Saved {kind} • scr {scroll_idx} • {status} • {len(body_bytes)}B • fn={friendly or 'None'} • json=True • serp={is_serp}")
            else:
                non_json += 1
                print(f"[non-json] {kind} {status} • {url}")
            if kind=="GraphQL": graphql_saved+=1
            else: route_saved+=1
            with manifest_fp.open("a", newline="", encoding="utf-8-sig") as f:
                csv.writer(f).writerow([datetime.now().isoformat(timespec="seconds"),0,scroll_idx,status,len(body_bytes),
                                        friendly or "", doc_id or "", 1 if is_json else 0, 1 if is_serp else 0, kind, str(out_path), url])

        def on_response(resp):
            nonlocal graphql_seen, route_seen
            url = resp.url or ""
            try:
                if GRAPHQL_RE.search(url):
                    graphql_seen += 1
                    try: body, is_json = resp.text(), True
                    except Exception: body, is_json = resp.body(), False
                    bbytes = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
                    friendly, doc_id = get_req_meta(resp)
                    save_blob("graphql", current_scroll_idx, url, resp.status, bbytes, friendly, doc_id, is_json, is_search_serp(friendly), "GraphQL")
                elif ROUTE_RE.search(url):
                    route_seen += 1
                    try: body, is_json = resp.text(), True
                    except Exception: body, is_json = resp.body(), False
                    bbytes = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
                    friendly, doc_id = get_req_meta(resp)
                    save_blob("route", current_scroll_idx, url, resp.status, bbytes, friendly, doc_id, is_json, False, "Route")
            except Exception as ex: print(f"[resp-handler-error] {ex}")

        page.on("response", on_response)

        # --- Robust navigation ---
        def robust_goto(pg, url: str):
            print(f"[i] Navigating → {url}")
            try: pg.goto(url, wait_until="domcontentloaded", timeout=int(args.nav_timeout_s*1000))
            except PWTimeout:
                print("[!] Timeout on domcontentloaded; retrying 'load'…")
                try: pg.goto(url, wait_until="load", timeout=int(args.nav_timeout_s*1000))
                except PWTimeout: print("[!] Timeout on 'load'. Proceeding anyway.")
            cur = (pg.url or "").lower()
            if cur.startswith("about:") or "chrome://" in cur or "edge://" in cur:
                print(f"[!] Still on '{pg.url}'. Opening a fresh tab and retrying…")
                pg = context.new_page(); pg.on("response", on_response)
                try: pg.goto(url, wait_until="domcontentloaded", timeout=int(args.nav_timeout_s*1000))
                except Exception as e: print(f"[!] Retry navigation error: {e}")
            return pg

        page = robust_goto(page, args.link)

        print(f"[i] Initial buffer: {args.initial_buffer_s:.1f}s")
        time.sleep(args.initial_buffer_s)

        # --- Scroll ---
        try: last_h = page.evaluate("() => document.body.scrollHeight")
        except Exception: last_h = 0

        for i in range(args.scrolls):
            current_scroll_idx = i
            try:
                page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(0.25)
                new_h = page.evaluate("() => document.body.scrollHeight")
            except Exception as e:
                print(f"[!] Scroll eval error: {e}"); break
            print(f"[i] scroll {i+1}/{args.scrolls} • height={new_h}")
            time.sleep(args.per_scroll_s)
            if new_h <= last_h: print("[i] No more content; stopping."); break
            last_h = new_h

        print("[i] Final idle: 5s"); time.sleep(5)
        context.close()

        # --- HAR export ---
        if not args.no_har:
            print(f"[i] Waiting up to {args.har_wait_s:.1f}s for HAR to flush…")
            if wait_for_file(har_path, timeout_s=args.har_wait_s):
                if args.har_export:
                    try:
                        dest = Path(args.har_export)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(har_path, dest)
                        print(f"[✓] HAR exported to: {dest.resolve()}")
                    except Exception as e: print(f"[!] HAR export failed: {e}")
                else: print(f"[✓] HAR saved at: {har_path.resolve()}")
            else:
                print("[!] HAR not found or empty after waiting.")

    # --- Debug summary ---
    print("\n=== DEBUG SUMMARY ===")
    print(f"graphql_seen:  {graphql_seen}")
    print(f"route_seen:    {route_seen}")
    print(f"graphql_saved: {graphql_saved}")
    print(f"route_saved:   {route_saved}")
    print(f"non_json:      {non_json}")
    print(f"Session dir:   {session_dir.resolve()}")
    print(f"Manifest:      {manifest_fp.resolve()}")

if __name__ == "__main__":
    main()
