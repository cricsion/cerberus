---
name: gau
description: >-
  Pull the historical URL corpus for one authorized domain from the public
  web archives (wayback, commoncrawl, otx, urlscan) with gau, so testing
  starts from what actually existed — retired endpoints, forgotten params,
  old API versions. Genuinely inert without egress: this is an
  archive-fetching tool, not a scanner.
---

# gau — historical URL harvest from public archives

gau asks the archives which URLs ever *existed* for a domain. Unlike the
probe tools, `--network none` doesn't just limit it, it nullifies it:
archives live outside the container. Use it on lanes with granted egress,
against domains in your assigned scope only.

## In this environment

- **gau 2.2.4** (lc/gau) is preinstalled; never install.
- **Egress is required.** On the default `--network none` lane the archive
  fetch fails fast with connection errors — that is the correct behavior,
  not breakage. Say so in the report instead of retrying: on offline lanes
  the archive harvest simply is not available, and `katana` (live surface)
  plus the repo's route index are the correct local substitutes.
- Scope discipline: one authorized domain per run (`--subs` widens to its
  subdomains — only with the same scope grant). Dedupe results before any
  use; a single day of commoncrawl can starve your `execute` timeout.
- Keep runs small: `--threads 2-4`, blacklist binary extensions, write to
  `/work` (never paste archive dumps into the report raw).

## Running it

```bash
gau --threads 3 --subs --blacklist png,jpg,jpeg,gif,css,woff2 \
    target.example.com > /work/gau.txt
wc -l /work/gau.txt && sort -u /work/gau.txt | head -40

# privacy-relevant slices: parameter-bearing GETs first, dataset filters after
grep -E '\?(.*)=' /work/gau.txt | grep -oE '\?[^=]+=' | sort | uniq -c |
    sort -rn | head -20

# json out for pipeline use
gau --json --providers wayback,otx target.example.com > /work/gau.json
```

`--providers wayback,commoncrawl,otx,urlscan` narrows sources; `--from/
--to YYYYMM` bounds an era (e.g. "the old API version's window").

## Reading the output

Each line is a URL the archives saw at least once. What makes it
intelligence: retired endpoints (`/api/v1/…` next to the current `/v3`),
parameter names that may still be accepted, auth-adjacent paths no live
crawler will ever link. Confirm current behavior per-URL with `httpx` and
route survivors into the api/web technique skills — archive presence never
proves your target still serves it.

## What gau is not

A live scanner: nothing it returns reflects the *current* target unless a
probe confirms it. It stores no findings of its own — a deduplicated URL
list is a lead list, and its rows are third-party artifacts, so the
scope and authorization arguments belong to you.
