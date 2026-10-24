---
name: httpx
description: >-
  Probe a list of in-scope HTTP(S) candidates for liveness, status, title,
  tech-detect, and CDN/WAF placement with projectdiscovery httpx. Use to
  turn a candidate list into a shortlist of live, characterizable services
  before fuzzing or crawling. Only meaningful on lanes with network access
  (or against targets started inside the container on localhost).
---

# httpx — liveness and characterization for candidate URLs

httpx does **not** attack anything; it cheaply answers "is this alive, what
is it running, where does the edge sit?" so the heavier tools (ffuf, nuclei,
katana, sqlmap) run against fewer, better-characterized targets.

## In this environment

- **httpx 1.12.0** (projectdiscovery) is preinstalled; never install.
- The sandbox's default posture is egress-denied (`--network none`): external
  probes fail fast with connection errors — that is the lane, not a tool
  bug. Two working profiles:
  - **localhost targets**: start the under-test app in the container
    (`python3 -m http.server` or your unit's service), then probe
    `127.0.0.1:<port>` — loopback works on every lane.
  - **granted lanes**: once a run profile allows egress, probe only hosts in
    your unit's assigned scope. Never probe external/public hosts by
    convenience — they are out of scope by definition.
- Output discipline: `-json` to a file under `/work`, parse with `jq`, cap
  with `head`. Each `execute` dies after ~120s; keep lists bounded and
  threads modest (`-p 50` is plenty; more just burns the timeout).

## Running it

```bash
# single in-container target, human-readable
httpx -u http://127.0.0.1:8080 -status-code -title -tech-detect -cdn

# a candidate list, machine-readable
cat /work/candidates.txt | httpx -json -status-code -cdn -location \
    -no-color > /work/httpx.json
jq -r '.["status-code"]' /work/httpx.json 2>/dev/null | sort | uniq -c

# pairs with a local listener: probe the SPA/API your unit ships
httpx -u http://127.0.0.1:3000 -u http://127.0.0.1:8000 -json -probe
```

`-probe` is the truth flag when results look empty: it prints the actual
per-host probe result instead of filtering failures to zero rows.

## Reading the output

JSONL — one object per response: `url`, `status-code`, `webserver`,
`content-type`, `title`, (`tech`/`cdn` pairs when enabled). A row is a
*service*, not a finding. Route the survivors: live app servers → ffuf/
katana/web runbooks; admin-ish titles or tech banners → their technique
skills; `cdn: true` rows are edge-served, and origin-direct testing is a
scope question to raise, not a bug.

## What httpx is not

A fuzzer or a scanner — unknown endpoints, parameter names, and
vulnerabilities are other tools' work. A dead host is evidence of path dead,
not of a blocked scanner; verify with `-probe` before concluding anything
about the URL list you were given.
