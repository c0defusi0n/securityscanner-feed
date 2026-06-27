# securityscanner-feed

Magento / Adobe Commerce **vulnerability watch feed** consumed by the
[C0defusi0n Magento SecurityScanner](https://github.com/c0defusi0n/SecurityScanner) module.

The module fetches [`feed.json`](feed.json) over HTTPS and surfaces the items in the admin: a
**system-message bar at the top** of every page and the **notification inbox** (the bell),
de-duplicated by `id`. The module only *consumes* this file — it is meant to be produced
**out-of-band** (e.g. a scheduled AI job aggregating Adobe APSB / NVD / Sansec).

## Use it

In the Magento admin (*Stores ▸ Configuration ▸ C0DEFUSI0N ▸ Security Scanner ▸ Magento Vulnerability Feed*):

1. Enable **Vulnerability Feed**.
2. Set the **Feed JSON URL** to the raw URL of this file, e.g.
   `https://raw.githubusercontent.com/c0defusi0n/securityscanner-feed/main/feed.json`

Fork and point the module at your fork to curate your own feed.

## Format

```json
{
  "updated": "2026-06-27T08:00:00Z",
  "items": [
    { "id": "APSB25-94", "severity": "critical",
      "title": "Adobe Commerce — unrestricted file upload (PolyShell)",
      "published": "2025-XX-XX",
      "url": "https://helpx.adobe.com/security/products/magento/apsb25-94.html",
      "summary": "Crafted upload → RCE. Apply the isolated patch." }
  ]
}
```

- `severity` ∈ `critical|high|medium|low` (defaults to `medium`). `url` must be http(s) or it is
  dropped. Keep `id` stable per vulnerability (use the APSB/CVE id) — it dedupes inbox notices.
- **Always include the authoritative `url`**: if the feed is AI-generated, the link lets an admin
  verify the summary. The module escapes all feed content on display.

## Auto-generation

A typical setup is a scheduled job (GitHub Action or a scheduled Claude Code routine) that
aggregates Adobe APSB + NVD/CVE + Sansec, asks an LLM to extract the latest Magento items into the
shape above, and commits this file. The module refreshes its cache hourly and shows the latest.
