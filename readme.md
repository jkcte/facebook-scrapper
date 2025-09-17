# Facebook HAR Text Extractor — README

> **Scope:** This README is for teammates who will **run the parser on already-captured HAR files**.
> It also documents **two ways to capture** a HAR (manual DevTools export and the live interceptor), so you know how to generate inputs for the parser.

---

## TL;DR

1. Capture a HAR from Facebook (either via **DevTools → Save all as HAR with content** or your **live interceptor**).
2. Run the parser:

```bash
pip install chardet
python har_extract_fb_serp.py "path\to\your.har" --out results.csv
```

You’ll get a CSV with columns:

```
text, timestamp_utc, timestamp_manila, permalink, friendly_name, doc_id, entry_index, mode
```

---

## Requirements

* **OS:** Windows
* **Python:** 3.17 (your current environment). Any modern 3.x should also work.
* **Python deps:** `chardet` (for robust body decoding)

Install once:

```bash
pip install chardet
```

---

## Repo layout

```
/ (repo root)
├─ facebookScrape.py             # the live interceptor that captures HARs
├─ har_extract_fb_serp.py        # the HAR interpreter / parser (GraphQL + route bundles)
└─ data/                         # (optional) put raw HARs here
```

> If you store HARs elsewhere, pass the full path to the parser.

---

## How it works (mechanics)

The parser reads each `log.entries[*]` in the HAR and tries to decode `response.content.text`.
It then **auto-detects** which kind of Facebook payload it is:

1. **GraphQL** (`https://www.facebook.com/api/graphql`)
2. **Route bundle** (`/ajax/bulk-route-definitions`), which Facebook returns when opening certain dialogs/routes

It extracts post text from **both** sources and writes to CSV.

### High-level architecture

```
             ┌────────────────────────┐
             │  HAR (raw network)     │
             │  log.entries[*]        │
             └──────────┬─────────────┘
                        │
               decode & strip FB prefix
                        │
          ┌─────────────┴─────────────┐
          │                           │
   GraphQL entries              Route bundle entries
 (api/graphql)                  (ajax/bulk-route-definitions)
          │                           │
   A) SERP path                   C) Route exports
  data.serpResponse...              payload(.payloads)[key]
  → edges → ... → story             → result.exports.meta.title
  → comet_sections → content → ...  → result.exports.rootView.props.headerTitle
  → message.text
          │                           │
   B) Generic fallback           (timestamps/permalink usually N/A)
  any {"message": {...text...}}
          │
  (timestamps/permalink best-effort)
          │
          └──────────┬─────────────┘
                     │
                CSV writer
```

### What fields we actually read

#### A) GraphQL SERP (fast path)

* **URL:** `https://www.facebook.com/api/graphql/`
* **Shape:**
  `data.serpResponse.results.edges[]`

  ```
  edge.rendering_strategy.view_model.click_model.story
      .comet_sections.content.story.message.text
  ```
* **Mode emitted:** `exact`
  (Or `fallback` if Facebook returns the slightly older `view_model.click_model.story` path.)

#### B) GraphQL generic message fallback

* If `serpResponse` isn’t present, we recursively search any `{"message": {...}}` blocks and pull a “best” text.
* **Mode emitted:** `generic`

> For GraphQL, we also try to infer:
>
> * **timestamp** via `creation_time` (or first epoch-like int we can find),
> * **permalink** via common key names and URL pattern scanning,
> * **friendly\_name** from `X-FB-Friendly-Name` header or POST params (when present),
> * **doc\_id** from POST params (when present).

#### C) Route bundles (bulk route definitions)

* **URL contains:** `ajax/bulk-route-definitions`
* **Shape:**
  Either top-level `payloads` **or** `payload.payloads`, then:

  ```
  payloads[route_key].result.exports.meta.title
  payloads[route_key].result.exports.rootView.props.headerTitle
  ```
* **Mode emitted:**

  * `route:title`   (from `meta.title`)
  * `route:header`  (from `rootView.props.headerTitle`)
* For routes, timestamps/permalinks aren’t usually available → those CSV fields are left blank.

---

## Example (real post text we verified)

From your HAR, the text appears inside a **route bundle** (not GraphQL), e.g.:

```
payload.payloads["/groups/onepiyucommunity/posts/24391411420529641/..."].result.exports.meta.title
= "One Piyu Community | Hii ask ko lang if may pupunta ba sa luneta this 21 or orgs na pwede makisama 😁"

payload.payloads["/groups/onepiyucommunity/posts/..."].result.exports.rootView.props.headerTitle
= "Triz Canoy's post"
```

That produces CSV rows with:

* `mode=route:title` → “One Piyu Community | Hii ask ko lang if may pupunta ba sa luneta this 21 or orgs na pwede makisama 😁”
* `mode=route:header` → “Triz Canoy's post”

---

## Using the parser

### 1) Manual capture (DevTools)

1. Open Facebook in Chrome/Edge.
2. `F12` → **Network** tab → check “**Preserve log**”.
3. Perform your action (open profile search, click Posts tab, open a post dialog, scroll).
4. Right-click in Network → **Save all as HAR with content**.
5. Save as e.g. `data\sample.har`.

### 2) Live interceptor (autoscroll)

Use your `facebookScrape.py` to drive the browser (open URL, buffer, scroll, capture network).
It will produce a session folder/HAR. (E.g., you’ve used buffers of 10s before first scroll, then 5s per scroll.)
Once it has created the HAR, proceed to **run the parser**.

> Current plan of record:
>
> 1. Run **facebookScrape.py** (collect network)
> 2. Run **har\_extract\_fb\_serp.py** (parse network)

### 3) Parse the HAR

```bash
pip install chardet

# default output: har_extracted_texts.csv (in cwd)
python har_extract_fb_serp.py "data\sample.har"

# custom output filename
python har_extract_fb_serp.py "data\sample.har" --out "results.csv"

# keep only rows whose text contains a keyword (case-insensitive)
python har_extract_fb_serp.py "data\sample.har" --filter "walang pasok"
```

---

## Output schema (CSV)

Columns (fixed as requested):

| column             | description                                                                       |
| ------------------ | --------------------------------------------------------------------------------- |
| `text`             | Extracted text (post body, route title, or dialog header)                         |
| `timestamp_utc`    | ISO string (best-effort, GraphQL only when a creation\_time is found)             |
| `timestamp_manila` | ISO string converted to `Asia/Manila` (best-effort, GraphQL only)                 |
| `permalink`        | Best-effort permalink URL if we can infer one (GraphQL only)                      |
| `friendly_name`    | Facebook `X-FB-Friendly-Name` (if present in GraphQL request headers/params)      |
| `doc_id`           | GraphQL `doc_id` (if present)                                                     |
| `entry_index`      | Index of the HAR entry (for debugging)                                            |
| `mode`             | Extraction mode: `exact`, `fallback`, `generic`, `route:title`, or `route:header` |

---

## Debug output — how to read it

After a run, you’ll see a summary like:

```
[✓] Done parsing: sample.har
    GraphQL entries seen: 13
    GraphQL with serpResponse: 0
    Message path hits — exact(new): 0  |  fallback: 0  |  generic: 0
    Edges scanned (serp): 0
    Top GraphQL friendly names:
      • GroupsCometFeedRegularStoriesPaginationQuery: 3
      • ...
    Route entries seen: 2
    Route rows written: 4
    Top route canonical names:
      • comet.fbweb.CometSinglePostDialogRoute: 2
    Output CSV: C:\path\to\results.csv
```

Interpretation:

* **GraphQL with serpResponse = 0** → No search result edges; likely not on a search “Posts” page.
* **generic = 0** → No obvious `{"message": {...}}` bodies in your GraphQL payloads.
* **Route rows written > 0** → Text came from route bundles (dialogs, profile/group contextual routes), not GraphQL.

---

## Troubleshooting

**Rows = 0, but I know I saw content on screen**

* Your HAR may not include the specific request holding the text:

  * For search results, look for `SearchCometResultsPaginatedResultsQuery` in `Top GraphQL friendly names`.
  * For dialogs/routes, ensure `/ajax/bulk-route-definitions` is present under `Route entries seen`.
* Turn on **“Preserve log”** before you click/scroll.
* Reproduce the exact action **after** starting capture (e.g., open “Posts” tab, then scroll).
* If responses show `[non-json] text/html; charset=utf-8`, Facebook might have returned an HTML fallback → reload and try again.

**I got only route rows, no timestamps/permalinks**

* Route bundles usually don’t carry post creation times or canonical permalinks. That’s expected.
* If you need timestamps, capture GraphQL search results (Posts tab + scroll) so we can read `creation_time`.

**My text is in `meta.title` only (“Group | <post text>”)**

* That’s normal for dialog routes; we write `mode=route:title`.
* The dialog header (often “<Name>’s post”) is written with `mode=route:header`.

**Encoding issues / gibberish**

* Make sure `chardet` is installed.
* We also strip Facebook’s `for (;;);` guard automatically.

---

## Architecture (deeper dive)

### Parser pipeline (detailed)

```
HAR → entries[*] → response.content
   └─ decode (base64/utf-8) → strip "for (;;);"
       └─ parse JSON (or extract-first-JSON-object)
           ├─ if URL has api/graphql:
           │     ├─ if data.serpResponse present:
           │     │     └─ walk edges → ... → story → message → text  (mode=exact/fallback)
           │     └─ else:
           │           └─ recursively scan any {"message": {...}}     (mode=generic)
           │
           └─ if URL has ajax/bulk-route-definitions:
                 └─ for each payloads[route_key]:
                        - exports.meta.title                        (mode=route:title)
                        - exports.rootView.props.headerTitle        (mode=route:header)
```

**Timestamps**: For GraphQL, we try:

1. `story.comet_sections.context_layout...metadata.story.creation_time`,
2. `content.story.creation_time`,
3. first epoch-like integer anywhere in the edge (best-effort).

**Permalinks**: We try common fields (`permalink_url`, `url`, `permalink`) and regex scan for `story.php`/`permalink.php`.

---

## CLI workflow (current plan)

Although the fully integrated CLI is WIP, the expected flow is:

```
# 1) Collect network (live interceptor)
python facebookScrape.py --url "https://www.facebook.com/profile/100069113923869/search/?q=walang%20pasok" --scrolls 20

# 2) Parse the produced HAR
python har_extract_fb_serp.py "C:\path\to\generated.har" --out "manifest.csv"
```

> You can still **manually export** a HAR with DevTools if you prefer.

---

## Privacy, legality & platform ToS

* This tool **only parses HAR files you captured from your own browser session**.
* It **works on publicly available content** surfaced to your account.
* It **cannot** access or view **private messages or posts** that your account cannot already see.
* Always follow Facebook’s **Terms of Service** and your local data/priv-laws.
* Use rate limits and be respectful—don’t overload endpoints.

---

## Roadmap / Ideas

* Add optional columns: `canonicalRouteName`, `storyID`, `groupID`, `userID` (for route rows)
* Add a “merge mode” to correlate route and GraphQL rows for the same story
* Built-in **HAR validator** (list missing expected requests, e.g., “no bulk-route-definitions seen”)
* GUI wrapper to drag-and-drop a HAR and save CSV

---

## FAQ

**Q: Can it extract comments or reactions?**
A: Not in this version. We focus on **post body text**. Comments/reactions arrive via different queries; they can be added later.

**Q: Why do some rows have empty timestamps/permalinks?**
A: Those are **route** rows. Route bundles rarely carry those fields.

**Q: Will it work if I’m not logged in?**
A: You’ll only see public content. The HAR reflects whatever your session can fetch.

---

If you want me to ship this README as a `README.md` file in your repo layout, say the word and where to place it (root vs. `docs/`).
