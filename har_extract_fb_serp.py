import argparse, base64, csv, json, re, sys, collections
from pathlib import Path
from datetime import datetime, timezone

try:
    import chardet
except ImportError:
    chardet = None  # we'll fall back to utf-8 if missing

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

def decode_body_text(content: dict) -> str:
    if not content: return ""
    text = content.get("text")
    if text is None: return ""
    if content.get("encoding") == "base64":
        try:
            raw = base64.b64decode(text)
            enc = chardet.detect(raw).get("encoding") if chardet else "utf-8"
            return raw.decode(enc or "utf-8", errors="replace")
        except Exception:
            return ""
    return text

def try_parse_json_from_text(s: str):
    if not s: return None
    s = s.lstrip()
    if s.startswith("for (;;);"): s = s[10:].lstrip()
    try:
        return json.loads(s)
    except Exception:
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
            for e in edges: yield e

def get_story_text_node_exact(edge):
    try:
        story = (
            edge["rendering_strategy"]["view_model"]["click_model"]["story"]
            ["comet_sections"]["content"]["story"]
        )
        msg = story.get("message", {})
        # accept both message.text and message.text_with_entities.text
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
                elif kl in ("text_with_entities","attributed_text","ranges","aggregated_ranges"):
                    # these often contain nested 'text'
                    walk(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for it in o: walk(it)
        elif isinstance(o, str):
            if o.strip(): texts.append(o.strip())

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
    seen = set()

    out_path = Path(args.out)
    with out_path.open("w", newline="", encoding="utf-8-sig") as f_out:
        w = csv.writer(f_out)
        w.writerow(["text","timestamp_utc","timestamp_manila","permalink","friendly_name","doc_id","entry_index","mode"])

        for idx, e in enumerate(entries):
            req = e.get("request", {})
            resp = e.get("response", {})
            url = req.get("url", "")
            if "facebook.com/api/graphql" not in url:
                continue
            graphql_seen += 1

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

            content = resp.get("content", {})
            body_text = decode_body_text(content)
            parsed = try_parse_json_from_text(body_text)
            if parsed is None:
                continue

            # 1) serpResponse fast path
            payloads = parsed if isinstance(parsed, list) else [parsed]
            has_serp = any(bool(pl.get("data", {}).get("serpResponse")) for pl in payloads if isinstance(pl, dict))
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
                    if mode == "exact": exact_hits += 1
                    else: fallback_hits += 1
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

            # 2) Generic deep finder (no serpResponse)
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
            # Not strictly a “hit”, but helps you see which friendly names had zero text
            if not found_any:
                pass

    print(f"\n[✓] Done parsing: {har_path.name}")
    print(f"    GraphQL entries seen: {graphql_seen}")
    print(f"    GraphQL with serpResponse: {serp_jsons}")
    print(f"    Message path hits — exact(new): {exact_hits}  |  fallback: {fallback_hits}  |  generic: {generic_hits}")
    print(f"    Edges scanned (serp): {total_edges}")
    if friendly_hist:
        print("    Top friendly names:")
        for name, cnt in friendly_hist.most_common(12):
            print(f"      • {name}: {cnt}")
    print(f"    Output CSV: {out_path.resolve()}")

if __name__ == "__main__":
    main()