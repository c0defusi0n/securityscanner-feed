#!/usr/bin/env python3
"""
Generate/update feed.json: ask Gemini (with Google Search grounding) for the latest Magento /
Adobe Commerce vulnerabilities and write them in the schema the SecurityScanner module consumes.
Run by .github/workflows/update-feed.yml on a schedule.

Safety:
- Never overwrites feed.json with an empty/garbage result (a bad run leaves the last good feed).
- Only rewrites when the item set actually changed (ignores the volatile 'updated' timestamp),
  so unchanged runs produce no commit and no notification.
- Writes new_items.md (the GitHub issue body) only when genuinely new ids appear.
Pure stdlib — no pip install needed on the runner.
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

MODEL = os.environ.get("GEMINI_MODEL") or "gemini-2.5-flash"
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
FEED_PATH = os.environ.get("FEED_PATH") or "feed.json"
MAX_ITEMS = int(os.environ.get("MAX_ITEMS") or "15")
NEW_ITEMS_PATH = "new_items.md"
SIGNATURES_REPO = "https://github.com/c0defusi0n/securityscanner-signatures"

SYSTEM = (
    "You are a security research assistant compiling a Magento / Adobe Commerce vulnerability "
    "feed. Use Google Search to find the most recent and most severe vulnerabilities (Adobe "
    "Security Bulletins 'APSB', CVEs, Sansec research). Only include items you actually found and "
    "can cite with a real source URL — never invent CVE/APSB ids or URLs; if unsure, omit the item. "
    "Prefer the last ~120 days. Reply with ONLY a compact JSON object, no prose and no markdown "
    'fences, of the form: {"items":[{"id":"APSB25-XX or CVE-...","severity":"critical|high|medium|low",'
    '"title":"...","published":"YYYY-MM-DD","url":"https://...","summary":"1-2 factual sentences"}]}'
)
USER = (
    f"Search the web and return up to {MAX_ITEMS} of the latest Magento / Adobe Commerce security "
    "vulnerabilities as the JSON object described. Sort most recent / most severe first. Output the JSON now."
)


def gemini_text(system, user):
    """One grounded generateContent call. Returns the concatenated text, or None on no/blocked output."""
    key = os.environ["GEMINI_API_KEY"]
    payload = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "tools": [{"google_search": {}}],   # web search grounding (Gemini 2.x+)
        "generationConfig": {"temperature": 0, "maxOutputTokens": 8192},
    }
    req = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), method="POST", headers={
        "x-goog-api-key": key,
        "content-type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            resp = json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"Gemini HTTP {e.code}: {e.read().decode(errors='replace')[:500]}", file=sys.stderr)
        # Config problems (bad key/model/request) → fail loudly; transient → leave feed untouched.
        sys.exit(1 if e.code in (400, 401, 403, 404) else 0)
    except Exception as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(0)
    cands = resp.get("candidates") or []
    if not cands:
        print(f"No candidates (promptFeedback={resp.get('promptFeedback')})", file=sys.stderr)
        return None
    parts = (cands[0].get("content") or {}).get("parts") or []
    return "".join(p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p)


def parse_items(text):
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except Exception:
        return None
    raw = data.get("items") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return None
    out, seen = [], set()
    for it in raw:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title", "")).strip()
        url = str(it.get("url", "")).strip()
        if not title or not (url.startswith("http://") or url.startswith("https://")):
            continue
        sev = str(it.get("severity", "")).strip().lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "medium"
        iid = str(it.get("id", "")).strip() or title[:60]
        if iid in seen:
            continue
        seen.add(iid)
        out.append({
            "id": iid,
            "severity": sev,
            "title": title,
            "published": str(it.get("published", "")).strip(),
            "url": url,
            "summary": str(it.get("summary", "")).strip(),
        })
        if len(out) >= MAX_ITEMS:
            break
    return out


def items_key(items):
    """Stable signature of the item set, ignoring the volatile 'updated' timestamp."""
    norm = sorted(
        [{k: i.get(k, "") for k in ("id", "severity", "title", "published", "url", "summary")} for i in items],
        key=lambda i: i["id"],
    )
    return json.dumps(norm, sort_keys=True, ensure_ascii=False)


def load_old():
    try:
        with open(FEED_PATH, encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("items", [])
        return items if isinstance(items, list) else []
    except Exception:
        return []


def main():
    new = parse_items(gemini_text(SYSTEM, USER))
    if not new:
        print("No usable items returned; leaving feed.json unchanged.")
        return
    old = load_old()
    if items_key(new) == items_key(old):
        print("Feed unchanged.")
        return

    with open(FEED_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {"updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "items": new},
            f, ensure_ascii=False, indent=2,
        )
        f.write("\n")

    old_ids = {i.get("id") for i in old}
    added = [i for i in new if i["id"] not in old_ids]
    print(f"feed.json updated: {len(new)} items, {len(added)} new.")
    if added:
        with open(NEW_ITEMS_PATH, "w", encoding="utf-8") as f:
            f.write(f"Automated scan found **{len(added)} new** Magento / Adobe Commerce vulnerability item(s).\n\n")
            for i in added:
                f.write(f"- **{i['id']}** ({i['severity']}) — {i['title']}  \n  {i['url']}\n")
            f.write(
                "\n---\n\n**Action:** review these and, for any that a regex can catch, add a signature to "
                f"[`securityscanner-signatures`]({SIGNATURES_REPO})'s `signatures.json` "
                "(the daily signature-proposer PR may already include some).\n"
            )


if __name__ == "__main__":
    main()
