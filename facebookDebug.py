# fb_debug_graphql_capture_v2.py
# pip install playwright
# playwright install

import csv, json, time, hashlib, re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import parse_qs
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

SEARCH_URL = "https://www.facebook.com/profile/100069113923869/search/?q=walang%20pasok"

HEADLESS               = False
INITIAL_BUFFER_SEC     = 10
PER_SCROLL_WAIT_SEC    = 5
QUIET_SEC_AFTER_SCROLL = 2.5
FINAL_IDLE_SEC         = 5
MAX_SCROLLS            = 20
RELOAD_CYCLES          = 1
WAIT_BETWEEN_RELOADS_SEC = 3

OUT_ROOT     = Path("debug_graphql_cap_v2")
COOKIES_PATH = Path("fb_cookies.json")

FB_GRAPHQL_MATCH = ("/api/graphql", "/api/graphqlbatch")
FB_HOST_HINTS    = (".facebook.com",)

# Try to click the "Posts" tab on the profile search page (multi-locale)
TAB_LABELS = [
    r"^Posts$", r"^Mga Post$", r"^Mga\s*Mga\s*Post$", r"^Public Posts$", r"^Mga Pampublikong Post$"
]

def ts_iso(ts=None): return datetime.fromtimestamp(ts or time.time(), tz=timezone.utc).isoformat()
def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)

def save_cookies(ctx, path=COOKIES_PATH):
    path.write_text(json.dumps(ctx.cookies(), ensure_ascii=False, indent=2), encoding="utf-8")
def load_cookies(ctx, path=COOKIES_PATH):
    if path.exists():
        ctx.add_cookies(json.loads(path.read_text(encoding="utf-8"))); return True
    return False

def is_fb_graphql(url: str) -> bool:
    return any(h in url for h in FB_HOST_HINTS) and any(s in url for s in FB_GRAPHQL_MATCH)

def short_sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()[:12]

def parse_graphql_request(req):
    info = {
        "method": req.method,
        "url": req.url,
        "headers": dict(req.headers),
        "resource_type": req.resource_type,
        "doc_id": None,
        "friendly_name": None,
        "variables": None,
        "raw_post_data": None,
    }
    # header-based friendly name (seen in your capture)
    fn = info["headers"].get("x-fb-friendly-name") or info["headers"].get("x-fb-friendly-name".lower())
    if fn: info["friendly_name"] = fn

    try:
        pd = req.post_data() or ""
        info["raw_post_data"] = pd
        if pd:
            form = parse_qs(pd)
            info["doc_id"] = form.get("doc_id", [None])[0]
            friendly = form.get("fb_api_req_friendly_name", [None])[0]
            info["friendly_name"] = info["friendly_name"] or friendly
            variables = form.get("variables", [None])[0]
            if variables:
                try: info["variables"] = json.loads(variables)
                except Exception: info["variables"] = variables
    except Exception:
        pass
    return info

def try_parse_json(body: bytes):
    if not body: return None
    s = body.decode("utf-8", errors="replace").lstrip()
    # Strip anti-JSON-hijack prefix if present
    if s.startswith("for (;;);"):
        s = s[10:].lstrip()
    try:
        return json.loads(s)
    except Exception:
        return None

def click_posts_tab(page):
    # Try common roles/selectors; ignore errors
    for pat in TAB_LABELS:
        try:
            # role=link or role=tab with text matching
            page.get_by_role("link", name=re.compile(pat, re.I)).first.click(timeout=1500)
            return True
        except PWTimeout:
            pass
        except Exception:
            pass
        try:
            page.get_by_role("tab", name=re.compile(pat, re.I)).first.click(timeout=1500)
            return True
        except PWTimeout:
            pass
        except Exception:
            pass
    return False

def main():
    session_dir = OUT_ROOT / f"session_{int(time.time())}"
    ensure_dir(session_dir)
    manifest_csv = session_dir / "manifest.csv"
    mf = manifest_csv.open("w", newline="", encoding="utf-8")
    mw = csv.writer(mf)
    mw.writerow([
        "cycle","scroll_idx","ts_iso",
        "req_method","req_res_type","status","content_type",
        "url","friendly_name","doc_id",
        "is_json","has_serp","json_hash",
        "req_json_path","res_body_path","res_json_path",
        "req_size","res_size"
    ])

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=HEADLESS)
        ctx = browser.new_context()
        page = ctx.new_page()

        if not load_cookies(ctx):
            page.goto("https://www.facebook.com/login.php", wait_until="domcontentloaded")
            print("Log in, then press Enter here…"); input(); save_cookies(ctx)

        last_graphql_at = 0.0

        def save_event(req, resp, cycle, scroll_idx):
            nonlocal last_graphql_at
            url = req.url
            if not is_fb_graphql(url): return
            ts = time.time(); last_graphql_at = ts
            info = parse_graphql_request(req)

            # Files
            cycle_dir = session_dir / f"cycle_{cycle:02d}"
            scroll_dir = cycle_dir / f"scroll_{scroll_idx:03d}"
            ensure_dir(scroll_dir)
            base = f"{int(ts*1000)}"

            # Request meta
            req_path = scroll_dir / f"req_{base}.json"
            req_path.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
            req_size = len(info.get("raw_post_data") or "")

            # Response raw
            status = None; ctype = ""; body = b""
            try:
                status = resp.status
                ctype = resp.headers.get("content-type", "")
                body = resp.body() or b""
            except Exception: pass
            res_body_path = scroll_dir / f"res_{base}.bin"
            res_body_path.write_bytes(body)
            res_size = len(body)

            # Try JSON parse regardless of content-type
            parsed = try_parse_json(body)
            is_json = parsed is not None
            has_serp = False
            json_hash = ""
            res_json_path = ""
            if is_json:
                # GraphQL may be list or dict (batch vs single)
                payloads = parsed if isinstance(parsed, list) else [parsed]
                for pl in payloads:
                    try:
                        if pl.get("data", {}).get("serpResponse"): has_serp = True; break
                    except Exception: pass
                json_hash = short_sha1(body)
                res_json_path = scroll_dir / f"res_{base}.json"
                res_json_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
                res_json_path = str(res_json_path.relative_to(session_dir))
            else:
                res_json_path = ""

            mw.writerow([
                cycle, scroll_idx, ts_iso(ts),
                info["method"], info["resource_type"], status, ctype,
                url, info["friendly_name"], info["doc_id"],
                int(is_json), int(has_serp), json_hash,
                str(req_path.relative_to(session_dir)),
                str(res_body_path.relative_to(session_dir)),
                res_json_path,
                req_size, res_size
            ])
            mf.flush()

            tag = f"{info['friendly_name'] or ''}".strip()
            print(f"[✓] GraphQL saved • cyc {cycle} • scr {scroll_idx} • {status} • "
                  f"{res_size}B • fn={tag or '-'} • json={is_json} • serp={has_serp}")

        def on_request_finished(req):
            try:
                resp = req.response()
                if resp: save_event(req, resp, current_cycle, current_scroll_idx)
            except Exception as e:
                print(f"[warn] requestfinished error: {e}")

        page.on("requestfinished", on_request_finished)

        for current_cycle in range(RELOAD_CYCLES):
            current_scroll_idx = -1
            if current_cycle == 0: page.goto(SEARCH_URL, wait_until="domcontentloaded")
            else: page.reload(wait_until="domcontentloaded")

            if INITIAL_BUFFER_SEC: time.sleep(INITIAL_BUFFER_SEC)

            # Try to switch to Posts tab to trigger serpResponse
            try:
                switched = click_posts_tab(page)
                if switched: time.sleep(2.0)
            except Exception: pass

            last_h = 0
            for si in range(MAX_SCROLLS):
                current_scroll_idx = si
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(PER_SCROLL_WAIT_SEC)

                # quiet window
                start_wait = time.time()
                while True:
                    now = time.time()
                    if last_graphql_at == 0.0:
                        if (now - start_wait) >= QUIET_SEC_AFTER_SCROLL: break
                    else:
                        if (now - last_graphql_at) >= QUIET_SEC_AFTER_SCROLL: break
                    time.sleep(0.25)

                new_h = page.evaluate("document.body.scrollHeight")
                print(f"[i] cycle {current_cycle} • scroll {si+1}/{MAX_SCROLLS} • height={new_h}")
                if new_h == last_h:
                    print("[i] No more content; stopping scroll."); break
                last_h = new_h

            if FINAL_IDLE_SEC: time.sleep(FINAL_IDLE_SEC)
            if current_cycle < RELOAD_CYCLES-1 and WAIT_BETWEEN_RELOADS_SEC:
                time.sleep(WAIT_BETWEEN_RELOADS_SEC)

        browser.close(); mf.close()
        print(f"\n[✓] Capture complete.\nSession: {session_dir.resolve()}\nManifest: {manifest_csv.resolve()}")

if __name__ == "__main__":
    main()
