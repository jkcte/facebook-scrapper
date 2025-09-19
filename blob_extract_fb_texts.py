#!/usr/bin/env python3
# blob_extract_fb_texts.py
#
# Parse JSON blobs saved by facebookScrape.py (cycle_*/*.json) using manifest.csv.
# Extracts:
#  1) GraphQL SERP messages: data -> serpResponse -> results -> edges[] -> ... story.message.(text|text_with_entities.text)
#  2) Generic GraphQL message objects: any {"message": {...text...}} in the JSON
#  3) Route bundles (ajax/bulk-route-definitions): exports.meta.title / rootView.props.headerTitle
#
# Output CSV columns (same as har_extract_fb_serp.py):
#   text, timestamp_utc, timestamp_manila, permalink, friendly_name, doc_id, entry_index, mode
#
# Usage:
#   python blob_extract_fb_texts.py --session "path\to\session_XXXXXXXXXXXX" --out results.csv [--filter "keyword"]
#
import argparse, base64, csv, json, re, sys, collections
from pathlib import Path
from datetime import datetime, timezone

try:
    import chardet
except ImportError:
    chardet = None

PERM_RE = re.compile(r"https?://(?:www|m|mbasic)\.facebook\.com/[^ \"]+?(?:story\.php|permalink\.php)[^ \"]*", re.I)

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
    except Exception: return ""

def strings_from(obj):
    out = []
    if isinstance(obj, dict):
        for v in obj.values(): out.extend(strings_from(v))
    elif isinstance(obj, list):
        for it in obj: out.extend(strings_from(it))
    elif isinstance(obj, str): out.append(obj)
    return out

def guess_permalink(node):
    if isinstance(node, dict):
        for key in ("permalink_url","url","permalink"):
            val = node.get(key)
            if isinstance(val, str) and "facebook.com" in val:
                return val
    for s in strings_from(node):
        m = PERM_RE.search(s)
        if m: return m.group(0)
    return ""

def first_epoch_like(obj, lo=1_420_000_000, hi=2_080_000_000):
    if isinstance(obj, dict):
        for v in obj.values():
            ts = first_epoch_like(v, lo, hi)
            if ts is not None: return ts
    elif isinstance(obj, list):
        for it in obj:
            ts = first_epoch_like(it, lo, hi)
            if ts is not None: return ts
    elif isinstance(obj, int) and lo <= obj <= hi:
        return obj
    return None

def load_text(path: Path) -> str:
    raw = path.read_bytes()
    # try text
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        enc = chardet.detect(raw).get("encoding") if chardet else "utf-8"
        return raw.decode(enc or "utf-8", errors="replace")

def strip_fb_prefix(s: str) -> str:
    s = s.lstrip()
    if s.startswith("for (;;);"): s = s[10:].lstrip()
    return s

def extract_first_json_object(s: str):
    start = s.find("{")
    if start == -1: return None
    depth = 0; in_str = False; esc = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == '"': in_str = False
        else:
            if ch == '"': in_str = True
            elif ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return s[start:i+1]
    return None

def try_parse_json_from_text(s: str):
    if not s: return None
    s2 = strip_fb_prefix(s)
    try:
        return json.loads(s2)
    except Exception:
        frag = extract_first_json_object(s2)
        if frag:
            try: return json.loads(frag)
            except Exception: return None
        return None

# -------- SERP helpers --------
def extract_edges_from_serp(parsed):
    payloads = parsed if isinstance(parsed, list) else [parsed]
    for pl in payloads:
        try:
            edges = pl["data"]["serpResponse"]["results"]["edges"]
        except Exception:
            continue
        if isinstance(edges, list):
            for e in edges: yield e

def get_story_text_node_exact(edge):
    try:
        story = (
            edge["rendering_strategy"]["view_model"]["click_model"]["story"]
            ["comet_sections"]["content"]["story"]
        )
        msg = story.get("message", {})
        if isinstance(msg, dict):
            if isinstance(msg.get("text"), str): return msg["text"], story
            twe = msg.get("text_with_entities")
            if isinstance(twe, dict) and isinstance(twe.get("text"), str):
                return twe["text"], story
        return None, None
    except Exception:
        return None, None

def get_story_text_node_fallback(edge):
    try:
        story = (
            edge["view_model"]["click_model"]["story"]
            ["comet_sections"]["content"]["story"]
        )
        msg = story.get("message", {})
        if isinstance(msg, dict):
            if isinstance(msg.get("text"), str): return msg["text"], story
            twe = msg.get("text_with_entities")
            if isinstance(twe, dict) and isinstance(twe.get("text"), str):
                return twe["text"], story
        return None, None
    except Exception:
        return None, None

def find_creation_time(edge, story_node):
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
    if isinstance(story_node, dict) and isinstance(story_node.get("creation_time"), int):
        return story_node["creation_time"]
    return first_epoch_like(edge)

# -------- generic message finder --------
def collect_texts_from_message_obj(msg_obj):
    texts = []
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                kl = k.lower()
                if kl in ("text","body","title"):
                    if isinstance(v, str) and v.strip():
                        texts.append(v.strip())
                elif kl in ("text_with_entities","attributed_text","ranges","aggregated_ranges"):
                    walk(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for it in o: walk(it)
        elif isinstance(o, str):
            if o.strip(): texts.append(o.strip())
    walk(msg_obj)
    texts = sorted(set(texts), key=lambda s: len(s), reverse=True)
    return texts[0] if texts else None

def find_message_nodes_generic(obj):
    if isinstance(obj, dict):
        if "message" in obj and isinstance(obj["message"], dict):
            best = collect_texts_from_message_obj(obj["message"])
            if isinstance(best, str) and best.strip():
                yield best, obj
        for v in obj.values():
            yield from find_message_nodes_generic(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from find_message_nodes_generic(it)

# -------- route bundle extractor --------
def extract_route_payloads(parsed):
    objs = parsed if isinstance(parsed, list) else [parsed]
    roots = []
    for obj in objs:
        if not isinstance(obj, dict): continue
        if isinstance(obj.get("payloads"), dict):
            roots.append(obj["payloads"])
        if isinstance(obj.get("payload"), dict) and isinstance(obj["payload"].get("payloads"), dict):
            roots.append(obj["payload"]["payloads"])
    for payloads in roots:
        for pkey, pval in payloads.items():
            if not isinstance(pval, dict): continue
            result = pval.get("result", {})
            exports = result.get("exports", {})
            meta = exports.get("meta", {}) if isinstance(exports, dict) else {}
            rootView = exports.get("rootView", {}) if isinstance(exports, dict) else {}
            props = rootView.get("props", {}) if isinstance(rootView, dict) else {}
            title = meta.get("title")
            header = props.get("headerTitle")
            extra = {
                "canonicalRouteName": exports.get("canonicalRouteName"),
                "actorID": exports.get("actorID"),
                "storyID": props.get("storyID"),
                "groupID": props.get("groupID"),
                "userID": props.get("userID"),
                "payload_key": pkey,
            }
            if isinstance(title, str) and title.strip():
                yield {"text": title.strip(), "mode": "route:title", **extra}
            if isinstance(header, str) and header.strip():
                yield {"text": header.strip(), "mode": "route:header", **extra}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True, help="Path to a session_XXXXXXXXXXXX folder (with manifest.csv).")
    ap.add_argument("--out", default="blob_extracted_texts.csv", help="Output CSV.")
    ap.add_argument("--filter", default=None, help="Keep only rows whose text contains this (case-insensitive).")
    args = ap.parse_args()

    session_dir = Path(args.session)
    manifest = session_dir / "manifest.csv"
    if not manifest.exists():
        print(f"[ERR] manifest not found: {manifest}")
        sys.exit(1)

    # Read manifest rows
    rows = list(csv.DictReader(manifest.open("r", encoding="utf-8-sig")))
    if not rows:
        print("[ERR] manifest is empty.")
        sys.exit(1)

    seen_keys = set()
    total_open = 0
    wrote = 0
    friendly_hist = collections.Counter()
    route_hist = collections.Counter()

    out_path = Path(args.out)
    with out_path.open("w", newline="", encoding="utf-8-sig") as f_out:
        w = csv.writer(f_out)
        w.writerow(["text","timestamp_utc","timestamp_manila","permalink","friendly_name","doc_id","entry_index","mode"])

        for idx, r in enumerate(rows):
            fp = Path(r["file_path"])
            if not fp.exists():
                continue
            total_open += 1
            try:
                body_text = load_text(fp)
            except Exception:
                continue
            parsed = try_parse_json_from_text(body_text)
            if parsed is None:
                continue

            friendly = r.get("friendly_name","") or ""
            doc_id = r.get("doc_id","") or ""
            kind = r.get("kind","") or ""
            if friendly: friendly_hist[friendly] += 1

            # ---- Route blobs ----
            if kind.lower() == "route":
                for hit in extract_route_payloads(parsed):
                    txt = hit["text"]
                    if args.filter and args.filter.lower() not in txt.lower():
                        continue
                    key = (txt, -1)
                    if key in seen_keys: continue
                    seen_keys.add(key)
                    wrote += 1
                    if hit.get("canonicalRouteName"): route_hist[hit["canonicalRouteName"]] += 1
                    w.writerow([txt, "", "", "", friendly, doc_id, idx, hit["mode"]])
                continue

            # ---- GraphQL blobs ----
            payloads = parsed if isinstance(parsed, list) else [parsed]
            has_serp = any(bool(pl.get("data", {}).get("serpResponse")) for pl in payloads if isinstance(pl, dict))
            if has_serp:
                for edge in extract_edges_from_serp(parsed):
                    # exact then fallback
                    text, story_node = get_story_text_node_exact(edge)
                    mode = "exact"
                    if not text:
                        text, story_node = get_story_text_node_fallback(edge)
                        mode = "fallback"
                    if not text or not story_node:
                        continue
                    if args.filter and args.filter.lower() not in text.lower():
                        continue
                    ts = find_creation_time(edge, story_node)
                    permalink = guess_permalink(story_node)
                    key = (text.strip(), int(ts) if ts is not None else -1)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    wrote += 1
                    w.writerow([text.strip(), to_utc_iso(ts), to_manila_iso(ts), permalink, friendly, doc_id, idx, mode])
                continue

            # generic message finder
            found = False
            for text, node in find_message_nodes_generic(parsed):
                found = True
                if args.filter and args.filter.lower() not in text.lower():
                    continue
                ts = first_epoch_like(node) or first_epoch_like(parsed)
                permalink = guess_permalink(node)
                key = (text.strip(), int(ts) if ts is not None else -1)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                wrote += 1
                w.writerow([text.strip(), to_utc_iso(ts), to_manila_iso(ts), permalink, friendly, doc_id, idx, "generic"])

    print(f"[✓] Done. Parsed blobs opened: {total_open}, rows written: {wrote}")
    if friendly_hist:
        print("    Top friendly names:")
        for name, cnt in friendly_hist.most_common(12):
            print(f"      • {name}: {cnt}")
    if route_hist:
        print("    Top route canonical names:")
        for name, cnt in route_hist.most_common(12):
            print(f"      • {name}: {cnt}")
    print(f"    Output CSV: {out_path.resolve()}")

if __name__ == "__main__":
    main()
