---
name: katana
description: >-
  Crawl an in-scope web target to enumerate routes, endpoints and JS-sourced
  resources with projectdiscovery katana (standard, non-headless mode). Use
  after httpx liveness and before fuzzing, to map the real attack surface
  instead of guessing paths. Loopback targets work on every lane; external
  targets need a granted lane.
---

# katana — surface enumeration by crawling

katana walks a target's links, forms, response JS and headers, and emits
every discoverable endpoint. Its product is a URL/endpoint list — the input
that makes ffuf/nuclei/sqlmap/httpx runs targeted instead of shotgun.

## In this environment

- **katana 1.8.0** (projectdiscovery) is preinstalled; never install.
- **Standard mode only.** `-headless`/`-hybrid` crawl with bundled-ish chrome
  from `--system-chrome-path` — **no chrome exists in this image**, so
  headless invocations fail with a browser error; do not use them.
- Scope is on your head: the crawler will follow links anywhere. Limit to
  the assigned host with `-u http://<one-host>` and keep depth small;
  `-nc` (no-color) and `-jvc`/json output land machine-parseable files
  under `/work`.
- Each `execute` dies after ~120s: keep `-d` at 2–3 and let re-runs deepen
  rather than one run blow the timeout. Rate-limit politely
  (`-c 10 -rl 30`), always.

## Running it

```bash
# the default arc: known files first, JS-aware, depth-bounded, json out
katana -u http://127.0.0.1:8080 -d 2 -c 8 -rl 30 -nc \
    -kf all -o /work/katana.json

# pull just the discovered endpoints for the next tool's input
jq -r 'try .request.endpoint // empty' /work/katana.json 2>/dev/null \
    | sort -u > /work/endpoints.txt
head -40 /work/endpoints.txt
```

`-kf all` fetches robots.txt and sitemap.xml results alongside crawled
links (needs depth ≥ 3 per its help — raise `-d` when known-files matter).

## Reading the output

Every line/JSON record is a discovered request: method, endpoint, source
(`crawl` vs `robots` vs `javascript`). Fieldname counts matter more than
novel paths: JS-sourced params feeding the same endpoint hint at client-side
routing that misses server checks. Endpoints are surface, not bugs — feed
them into the api/web technique skills' decision tables.

## What katana is not

A vulnerability scanner: it sends no injections, makes no schema claims, and
misses anything behind auth, JS-rendering (no headless lane here), or
non-GET routing that the target never links. A crawl that returns ten paths
and silence means "shallow reach", not "small surface" — record the depth
and thread count you used alongside the list.
