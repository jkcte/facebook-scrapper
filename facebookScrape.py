# fb_capture_and_parse.py
# pip install playwright
# playwright install

import csv, json, time, hashlib, re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import parse_qs
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

# =======================
# ULTRA-AGGRESSIVE KNOBS
# =======================
SEARCH_URL = "https://www.facebook.com/profile/100069113923869/search/?q=walang%20pasok"

HEADLESS                = False
INITIAL_BUFFER_SEC      = 4    # minimal as possible before starting scrolls
PER_SCROLL_WAIT_SEC     = 2   # tiny pause after each scroll
QUIET_SEC_AFTER_SCROLL  = 2   # wait until no new graphql for this long
FINAL_IDLE_SEC          = 5   # short cooldown at the end
MAX_SCROLLS             = 10_000 # per your ask

RELOAD_CYCLES           = 1      # keep 1 unless you explicitly want reloads
WAIT_BETWEEN_RELOADS_SEC= 0.0

# Keep only posts that match this keyword (case-insensitive). Set to None to keep all.
FILTER_KEYWORD = "walang pasok"

# Storage
OUT_ROOT     = Path("cap_and_parse_out")
COOKIES_PATH = Path("fb_cookies.json")

FB_GRAPHQL_MATCH = ("/api/graphql", "/api/graphqlbatch")
FB_HOST_HINTS    = (".facebook.com",)

TAB_LABELS = [
    r"^Posts$", r"^Mga Post$", r"^Public Posts$", r"^Mga Pampublikong Post$"
]

# =======================
# Helpers
# =======================
def ts_iso(ts=None): return datetime.fromtimestamp(ts or time.time(), tz=timezone.utc).isoformat()
def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)

def save_cookies(ctx): COOKIES_PATH.write_text(json.dumps(ctx.cookies(), ensure_ascii=False, indent=2), encoding="utf-8")
def load_cookies(ctx):
    if COOKIES_PATH.exists():
        ctx.add_cookies(json.loads(COOKIES_PATH.read_text(encoding="utf-8"))); return True
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
    # friendlier name often in header
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
    if s.startswith("for (;;);"): s = s[10:].lstrip()
    try: return json.loads(s)
    except Exception: return None

def click_posts_tab(page):
    for pat in TAB_LABELS:
        try:
            page.get_by_role("link", name=re.compile(pat, re.I)).first.click(timeout=800)
            return True
        except Exception: pass
        try:
            page.get_by_role("tab", name=re.compile(pat, re.I)).first.click(timeout=800)
            return True
        except Exception: pass
    return False

# ====== Parsing utilities for serpResponse edges ======
try:
    from zoneinfo import ZoneInfo
    PH_TZ = ZoneInfo("Asia/Manila")
except Exception:
    PH_TZ = None

def to_utc_iso(ts):
    if ts is None: return ""
    try: return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception: return ""

def to_manila_iso(ts):
    if ts is None: return ""
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        if PH_TZ: dt = dt.astimezone(PH_TZ)
        return dt.isoformat()
    except Exception:
        return ""

def strings_from(obj):
    out = []
    if isinstance(obj, dict):
        for v in obj.values(): out.extend(strings_from(v))
    elif isinstance(obj, list):
        for it in obj: out.extend(strings_from(it))
    elif isinstance(obj, str):
        out.append(obj)
    return out

_PERM_RE = re.compile(r"https?://(?:www|m|mbasic)\.facebook\.com/[^ \"]+?(?:story\.php|permalink\.php)[^ \"]*", re.I)
def guess_permalink(story_node):
    if isinstance(story_node, dict):
        for key in ("permalink_url","url","permalink"):
            val = story_node.get(key)
            if isinstance(val, str) and "facebook.com" in val: return val
    for s in strings_from(story_node):
        m = _PERM_RE.search(s)
        if m: return m.group(0)
    return ""

def get_story_text_and_node(edge):
    # New path (Opera GX capture)
    try:
        story = (
            edge["rendering_strategy"]["view_model"]["click_model"]["story"]
            ["comet_sections"]["content"]["story"]
        )
        return story["message"]["text"], story
    except Exception:
        # Rare fallback
        try:
            story = (
                edge["view_model"]["click_model"]["story"]
                ["comet_sections"]["content"]["story"]
            )
            return story["message"]["text"], story
        except Exception:
            return None, None

def find_creation_time(edge, story_node):
    # 1) context_layout → metadata[*] → story.creation_time
    try:
        meta = (
            edge["rendering_strategy"]["view_model"]["click_model"]["story"]
            ["comet_sections"]["context_layout"]["story"]["comet_sections"]["metadata"]
        )
        metas = meta if isinstance(meta, list) else [meta]
        for m in metas:
            st = m.get("story")
            if isinstance(st, dict) and isinstance(st.get("creation_time"), int):
                return st["creation_time"]
    except Exception:
        pass
    # 2) directly on content story
    if isinstance(story_node, dict) and isinstance(story_node.get("creation_time"), int):
        return story_node["creation_time"]
    # 3) first plausible epoch anywhere in the edge
    lo, hi = 1_420_000_000, 2_080_000_000  # ~2015..2035
    def scan(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                ts = scan(v)
                if ts is not None: return ts
        elif isinstance(obj, list):
            for it in obj:
                ts = scan(it)
                if ts is not None: return ts
        elif isinstance(obj, int) and lo <= obj <= hi:
            return obj
        return None
    return scan(edge)

def extract_from_serp_json(parsed_json):
    payloads = parsed_json if isinstance(parsed_json, list) else [parsed_json]
    for pl in payloads:
        try:
            edges = pl["data"]["serpResponse"]["results"]["edges"]
        except Exception:
            continue
        if not isinstance(edges, list): continue
        for e in edges:
            text, story_node = get_story_text_and_node(e)
            if not text or not story_node: continue
            ts = find_creation_time(e, story_node)
            permalink = guess_permalink(story_node)
            yield {"text": text.strip(), "ts": ts, "permalink": permalink}

# =======================
# Main
# =======================
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

            # files
            cycle_dir = session_dir / f"cycle_{cycle:02d}"
            scroll_dir = cycle_dir / f"scroll_{scroll_idx:05d}"  # 10k safe width
            ensure_dir(scroll_dir)
            base = f"{int(ts*1000)}"

            # request meta
            req_path = scroll_dir / f"req_{base}.json"
            req_path.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
            req_size = len(info.get("raw_post_data") or "")

            # response raw
            status = None; ctype = ""; body = b""
            try:
                status = resp.status
                ctype = resp.headers.get("content-type", "")
                body = resp.body() or b""
            except Exception: pass
            res_body_path = scroll_dir / f"res_{base}.bin"
            res_body_path.write_bytes(body)
            res_size = len(body)

            # parse JSON regardless of content-type
            parsed = try_parse_json(body)
            is_json = parsed is not None
            has_serp = False
            json_hash = ""
            res_json_path = ""
            if is_json:
                payloads = parsed if isinstance(parsed, list) else [parsed]
                for pl in payloads:
                    try:
                        if pl.get("data", {}).get("serpResponse"):
                            has_serp = True; break
                    except Exception: pass
                json_hash = short_sha1(body)
                res_json = scroll_dir / f"res_{base}.json"
                res_json.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
                res_json_path = str(res_json.relative_to(session_dir))

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

        def on_request_finished(req):
            try:
                resp = req.response()
                if resp: save_event(req, resp, current_cycle, current_scroll_idx)
            except Exception:
                pass

        page.on("requestfinished", on_request_finished)

        # -------- CAPTURE WITH TINY BUFFERS --------
        for current_cycle in range(RELOAD_CYCLES):
            current_scroll_idx = -1
            if current_cycle == 0: page.goto(SEARCH_URL, wait_until="domcontentloaded")
            else: page.reload(wait_until="domcontentloaded")

            # minimal initial wait
            if INITIAL_BUFFER_SEC: time.sleep(INITIAL_BUFFER_SEC)

            # try switch to "Posts" tab (fast)
            try:
                click_posts_tab(page)
            except Exception:
                pass

            last_h = 0
            for si in range(MAX_SCROLLS):
                current_scroll_idx = si
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                if PER_SCROLL_WAIT_SEC: time.sleep(PER_SCROLL_WAIT_SEC)

                # short quiet window
                start_wait = time.time()
                while True:
                    now = time.time()
                    if last_graphql_at == 0.0:
                        if (now - start_wait) >= QUIET_SEC_AFTER_SCROLL: break
                    else:
                        if (now - last_graphql_at) >= QUIET_SEC_AFTER_SCROLL: break
                    time.sleep(0.05)

                new_h = page.evaluate("document.body.scrollHeight")
                if new_h == last_h:
                    break
                last_h = new_h

            if FINAL_IDLE_SEC: time.sleep(FINAL_IDLE_SEC)
            if current_cycle < RELOAD_CYCLES-1 and WAIT_BETWEEN_RELOADS_SEC:
                time.sleep(WAIT_BETWEEN_RELOADS_SEC)

        browser.close()
        mf.close()

    # -------- PARSE → CSV (immediately after capture) --------
    manifest = manifest_csv
    out_csv = session_dir / "fb_extracted_texts.csv"

    # read manifest, parse only JSON with serp
    seen = set()
    kept = 0
    total_edges = 0

    with manifest.open("r", encoding="utf-8") as f_in, out_csv.open("w", newline="", encoding="utf-8") as f_out:
        rdr = csv.DictReader(f_in)
        w = csv.writer(f_out)
        w.writerow(["text","timestamp_utc","timestamp_manila","permalink","friendly_name","doc_id","cycle","scroll_idx","json_file"])
        for row in rdr:
            if row.get("is_json") != "1" or row.get("has_serp") != "1":
                continue
            json_rel = row.get("res_json_path") or ""
            if not json_rel: continue
            json_path = (session_dir / json_rel).resolve()
            try:
                parsed = json.loads(json_path.read_text(encoding="utf-8"))
            except Exception:
                continue

            payloads = parsed if isinstance(parsed, list) else [parsed]
            for pl in payloads:
                try:
                    edges = pl["data"]["serpResponse"]["results"]["edges"]
                except Exception:
                    continue
                if not isinstance(edges, list): continue
                for e in edges:
                    text, story_node = get_story_text_and_node(e)
                    if not text or not story_node: continue
                    if FILTER_KEYWORD and FILTER_KEYWORD.lower() not in text.lower():
                        continue
                    ts = find_creation_time(e, story_node)
                    permalink = guess_permalink(story_node)
                    total_edges += 1
                    key = (text.strip(), int(ts) if ts is not None else -1)
                    if key in seen: continue
                    seen.add(key); kept += 1
                    w.writerow([
                        text.strip(),
                        to_utc_iso(ts),
                        to_manila_iso(ts),
                        permalink,
                        row.get("friendly_name",""),
                        row.get("doc_id",""),
                        row.get("cycle",""),
                        row.get("scroll_idx",""),
                        json_rel
                    ])

    print(f"\n[✓] Capture+Parse complete.")
    print(f"Session dir: {session_dir.resolve()}")
    print(f"Manifest:    {manifest.resolve()}")
    print(f"Extracted:   {out_csv.resolve()}")
    print(f"Edges seen:  {total_edges} • Rows written: {kept}")

if __name__ == "__main__":
    main()
