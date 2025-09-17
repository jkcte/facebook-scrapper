#!/usr/bin/env python3
# https://www.facebook.com/groups/onepiyucommunity
# har_extract_fb_combined.py
#
# Parse Facebook HAR files for:
#  1) GraphQL search results (serpResponse → ... → story → message → text)
#  2) Generic GraphQL message objects (any {"message": {...text...}})
#  3) Bulk-route bundles (ajax/bulk-route-definitions) → exports.meta.title / rootView.props.headerTitle
#
# Outputs a CSV with columns:
#   text, timestamp_utc, timestamp_manila, permalink, friendly_name, doc_id, entry_index, mode
#
# Modes:
#   "exact"         : serpResponse → rendering_strategy path (new)
#   "fallback"      : serpResponse → view_model path (older/alt)
#   "generic"       : any GraphQL payload where a {"message": {...}} was found
#   "route:title"   : ajax/bulk-route-definitions → exports.meta.title
#   "route:header"  : ajax/bulk-route-definitions → rootView.props.headerTitle
#
# Usage:
#   pip install chardet
#   python har_extract_fb_combined.py OPC_graphQL2.har --out opc_results.csv
#
import argparse, base64, csv, json, re, sys, collections
from pathlib import Path
from datetime import datetime, timezone

try:
    import chardet
except ImportError:
    chardet = None  # we'll fall back to utf-8 if missing

# --- URL hints for what to process ---
GRAPHQL_HINT = "facebook.com/api/graphql"
ROUTE_URL_HINTS = ("ajax/bulk-route-definitions", "bulk-route-definitions")

# --- Permalink detection (best-effort) ---
PERM_RE = re.compile(r"https?://(?:www|m|mbasic)\.facebook\.com/[^ \"]+?(?:story\.php|permalink\.php)[^ \"]*", re.I)

# --- Manila timezone support (optional) ---
try:
    from zoneinfo import ZoneInfo
    PH_TZ = ZoneInfo("Asia/Manila")
except Exception:
    PH_TZ = None

def to_utc_iso(ts):
    if ts is None:
        return ""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return ""

def to_manila_iso(ts):
    if ts is None:
        return ""
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        if PH_TZ:
            dt = dt.astimezone(PH_TZ)
        return dt.isoformat()
    except Exception:
        return ""

def strings_from(obj):
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(strings_from(v))
    elif isinstance(obj, list):
        for it in obj:
            out.extend(strings_from(it))
    elif isinstance(obj, str):
        out.append(obj)
    return out

def guess_permalink(node):
    if isinstance(node, dict):
        for key in ("permalink_url", "url", "permalink"):
            val = node.get(key)
            if isinstance(val, str) and "facebook.com" in val:
                return val
    for s in strings_from(node):
        m = PERM_RE.search(s)
        if m:
            return m.group(0)
    return ""

def first_epoch_like(obj, lo=1_420_000_000, hi=2_080_000_000):
    # ~2015..2035
    if isinstance(obj, dict):
        for v in obj.values():
            ts = first_epoch_like(v, lo, hi)
            if ts is not None:
                return ts
    elif isinstance(obj, list):
        for it in obj:
            ts = first_epoch_like(it, lo, hi)
            if ts is not None:
                return ts
    elif isinstance(obj, int) and lo <= obj <= hi:
        return obj
    return None

def decode_body_text(content: dict) -> str:
    """Return decoded text from HAR response.content; handles base64 + encodings."""
    if not isinstance(content, dict):
        return ""
    text = content.get("text")
    if text is None:
        return ""
    if content.get("encoding") == "base64":
        try:
            raw = base64.b64decode(text)
            enc = chardet.detect(raw).get("encoding") if chardet else "utf-8"
            return raw.decode(enc or "utf-8", errors="replace")
        except Exception:
            return ""
    return text

def strip_fb_prefix(s: str) -> str:
    if not s:
        return s
    s = s.lstrip()
    if s.startswith("for (;;);"):
        return s[10:].lstrip()
    return s

def try_parse_json_from_text(s: str):
    if not s:
        return None
    s2 = strip_fb_prefix(s)
    try:
        return json.loads(s2)
    except Exception:
        # Sometimes FB sticks extra non-JSON around a valid object.
        frag = extract_first_json_object(s2)
        if frag:
            try:
                return json.loads(frag)
            except Exception:
                return None
        return None

def extract_first_json_object(s: str):
    """Extract first {...} JSON object by brace matching (handles strings/escapes)."""
    start = s.find('{')
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return s[start:i+1]
    return None

# ---- Known "serp" path (fast path when present)
def extract_edges_from_serp(parsed):
    payloads = parsed if isinstance(parsed, list) else [parsed]
    for pl in payloads:
        try:
            edges = pl["data"]["serpResponse"]["results"]["edges"]
        except Exception:
            continue
        if isinstance(edges, list):
            for e in edges:
                yield e

def get_story_text_node_exact(edge):
    try:
        story = (
            edge["rendering_strategy"]["view_model"]["click_model"]["story"]
            ["comet_sections"]["content"]["story"]
        )
        msg = story.get("message", {})
        # accept both message.text and message.text_with_entities.text
        if isinstance(msg, dict):
            if isinstance(msg.get("text"), str):
                return msg["text"], story
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
            if isinstance(msg.get("text"), str):
                return msg["text"], story
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

# ---- Generic message finder when there's NO serpResponse
def collect_texts_from_message_obj(msg_obj):
    """Return a 'best' text string from a message object by searching common fields."""
    texts = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                kl = k.lower()
                if kl in ("text", "body", "title"):
                    if isinstance(v, str) and v.strip():
                        texts.append(v.strip())
                elif kl in ("text_with_entities", "attributed_text", "ranges", "aggregated_ranges"):
                    # these often contain nested 'text'
                    walk(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for it in o:
                walk(it)
        elif isinstance(o, str):
            if o.strip():
                texts.append(o.strip())

    walk(msg_obj)
    # prefer the longest snippet (usually the main post text)
    texts = sorted(set(texts), key=lambda s: len(s), reverse=True)
    return texts[0] if texts else None

def find_message_nodes_generic(obj):
    """
    Yield (text, node) when we see any node that has a 'message' object with textual content,
    even if it's nested (e.g., message.text_with_entities.text).
    """
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

# ---- Route bundle extractor (ajax/bulk-route-definitions)
def extract_route_payloads(parsed):
    """
    Yield dicts with text + extras from route bundle responses.
    Supports both {"payload":{"payloads":{...}}} and {"payloads":{...}} shapes,
    and array-wrapped payloads.
    """
    objs = parsed if isinstance(parsed, list) else [parsed]
    roots = []
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        if isinstance(obj.get("payloads"), dict):
            roots.append(obj["payloads"])
        if isinstance(obj.get("payload"), dict) and isinstance(obj["payload"].get("payloads"), dict):
            roots.append(obj["payload"]["payloads"])

    for payloads in roots:
        for pkey, pval in payloads.items():
            if not isinstance(pval, dict):
                continue
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
    ap.add_argument("har", type=str, help="Path to HAR file")
    ap.add_argument("--filter", type=str, default=None,
                    help="Keep only messages containing this (case-insensitive). Omit to keep all.")
    ap.add_argument("--out", type=str, default="har_extracted_texts.csv",
                    help="Output CSV filename")
    args = ap.parse_args()

    har_path = Path(args.har)
    if not har_path.exists():
        print(f"ERR: HAR not found: {har_path}")
        sys.exit(1)

    # Load HAR
    try:
        har = json.loads(har_path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raw = har_path.read_bytes()
        enc = chardet.detect(raw).get("encoding") if chardet else "utf-8"
        har = json.loads(raw.decode(enc or "utf-8", errors="replace"))

    entries = har.get("log", {}).get("entries", [])
    if not entries:
        print("No entries found in HAR.")
        sys.exit(1)

    graphql_seen = 0
    serp_jsons = 0
    exact_hits = 0
    fallback_hits = 0
    generic_hits = 0
    total_edges = 0
    friendly_hist = collections.Counter()

    route_entries_seen = 0
    route_rows_written = 0
    route_canonical_hist = collections.Counter()

    seen = set()

    out_path = Path(args.out)
    with out_path.open("w", newline="", encoding="utf-8-sig") as f_out:
        w = csv.writer(f_out)
        w.writerow(["text","timestamp_utc","timestamp_manila","permalink","friendly_name","doc_id","entry_index","mode"])

        for idx, e in enumerate(entries):
            req = e.get("request", {})
            resp = e.get("response", {})
            url = req.get("url", "") or ""
            is_graphql = GRAPHQL_HINT in url
            is_route = any(h in url for h in ROUTE_URL_HINTS)
            if not (is_graphql or is_route):
                continue

            content = resp.get("content", {})
            body_text = decode_body_text(content)
            parsed = try_parse_json_from_text(body_text)
            if parsed is None:
                continue

            # --- Route bundles (handle first; many route responses don't resemble GraphQL)
            if is_route:
                route_entries_seen += 1
                for hit in extract_route_payloads(parsed):
                    txt = hit["text"]
                    if args.filter and args.filter.lower() not in txt.lower():
                        continue
                    key = (txt, -1)  # no reliable ts for route blobs
                    if key in seen:
                        continue
                    seen.add(key)
                    route_rows_written += 1
                    if hit.get("canonicalRouteName"):
                        route_canonical_hist[hit["canonicalRouteName"]] += 1
                    # Write row (no timestamps/permalink/friendly/doc_id)
                    w.writerow([txt, "", "", "", "", "", idx, hit["mode"]])
                # We handled route payload; continue to next entry
                continue

            # --- GraphQL handling ---
            if is_graphql:
                graphql_seen += 1
                # Try to detect friendly name + doc_id
                headers = {h.get("name","").lower(): h.get("value","") for h in req.get("headers",[])}
                friendly = headers.get("x-fb-friendly-name") or ""
                post_data = req.get("postData", {})
                doc_id = ""
                if isinstance(post_data, dict):
                    params = post_data.get("params", [])
                    kv = {p.get("name",""): p.get("value","") for p in params if isinstance(p, dict)}
                    doc_id = kv.get("doc_id","") or ""
                    if not friendly:
                        friendly = kv.get("fb_api_req_friendly_name","") or friendly
                if friendly:
                    friendly_hist[friendly] += 1

                payloads = parsed if isinstance(parsed, list) else [parsed]
                has_serp = any(bool(pl.get("data", {}).get("serpResponse")) for pl in payloads if isinstance(pl, dict))

                # 1) serpResponse fast path
                if has_serp:
                    serp_jsons += 1
                    for edge in extract_edges_from_serp(parsed):
                        total_edges += 1
                        text, story_node = get_story_text_node_exact(edge)
                        mode = "exact"
                        if not text:
                            text, story_node = get_story_text_node_fallback(edge)
                            mode = "fallback"
                        if not text or not story_node:
                            continue
                        if mode == "exact":
                            exact_hits += 1
                        else:
                            fallback_hits += 1
                        if args.filter and args.filter.lower() not in text.lower():
                            continue
                        ts = find_creation_time(edge, story_node)
                        permalink = guess_permalink(story_node)
                        key = (text.strip(), int(ts) if ts is not None else -1)
                        if key in seen:
                            continue
                        seen.add(key)
                        w.writerow([text.strip(), to_utc_iso(ts), to_manila_iso(ts), permalink, friendly, doc_id, idx, mode])
                    continue

                # 2) Generic deep finder (no serpResponse present)
                found_any = False
                for text, node in find_message_nodes_generic(parsed):
                    found_any = True
                    if args.filter and args.filter.lower() not in text.lower():
                        continue
                    ts = first_epoch_like(node) or first_epoch_like(parsed)
                    permalink = guess_permalink(node)
                    key = (text.strip(), int(ts) if ts is not None else -1)
                    if key in seen:
                        continue
                    seen.add(key)
                    generic_hits += 1
                    w.writerow([text.strip(), to_utc_iso(ts), to_manila_iso(ts), permalink, friendly, doc_id, idx, "generic"])
                # If not found_any, nothing to do for this GraphQL entry

    # --- Summary ---
    print(f"\n[✓] Done parsing: {har_path.name}")
    print(f"    GraphQL entries seen: {graphql_seen}")
    print(f"    GraphQL with serpResponse: {serp_jsons}")
    print(f"    Message path hits — exact(new): {exact_hits}  |  fallback: {fallback_hits}  |  generic: {generic_hits}")
    print(f"    Edges scanned (serp): {total_edges}")
    if friendly_hist:
        print("    Top GraphQL friendly names:")
        for name, cnt in friendly_hist.most_common(12):
            print(f"      • {name}: {cnt}")
    print(f"    Route entries seen: {route_entries_seen}")
    print(f"    Route rows written: {route_rows_written}")
    if route_canonical_hist:
        print("    Top route canonical names:")
        for name, cnt in route_canonical_hist.most_common(12):
            print(f"      • {name}: {cnt}")
    print(f"    Output CSV: {out_path.resolve()}")

if __name__ == "__main__":
    main()
