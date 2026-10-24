---
name: arjun
description: >-
  Discover hidden HTTP parameters on one in-scope endpoint with arjun:
  heuristic parameter mining (bundled wordlists, chunked probing, GET/POST/
  JSON/XML modes) that reveals reflected or behavior-changing yet
  undocumented params. Fully usable against targets started in-container on
  localhost — loopback traffic works on every lane, even egress-denied ones.
---

# arjun — hidden parameter discovery

Undocumented parameters are where logic checks live: debug flags, role
hints, internal redirects. arjun sends chunked candidate-name probes and
reports which names cause measurable differences (reflection, different
response codes/sizes). Its product is a parameter, not a vulnerability.

## In this environment

- **arjun 2.2.7** is preinstalled (pip); never install. Its wordlists ship
  inside the package (default `db/large.txt` — no `-w` needed).
- **Localhost is the reproducible lane**: point it at your unit's service
  started in the container (`127.0.0.1:<port>`); loopback works on the
  default `--network none` lane. External hosts need a granted lane and
  your unit's scope.
- Each `execute` dies after ~120s: one endpoint per run, `-t 5` threads,
  `--stable` when the target is rate-limited, JSON out under `/work`
  (`-o`). Many endpoints → `-i targets.txt` batches over multiple runs.
- `--passive` pulls parameter names from wayback/commoncrawl/otx — that
  needs egress (same honest boundary as gau) and only makes sense on
  granted lanes.

## Running it

```bash
# the standard arc, JSON out
arjun -u http://127.0.0.1:8080/api/v1/users -m GET -t 5 \
    -o /work/arjun-users.json

# browser-like probes when WAF/botsense rejects defaults
arjun -u http://127.0.0.1:9000 -m POST --stable --rate-limit 2 \
    --headers "User-Agent: Mozilla/5.0"
# --headers takes multiple headers (first, then read from the prompt)

# many endpoints, bounded
printf '%s\n' http://127.0.0.1:8080/a http://127.0.0.1:8080/b > /work/targets
arjun -i /work/targets -m GET -o /work/arjun-multi.json
```

## Reading the output

Per-target tables: parameter name, then how it changed the response
(reflected text, different status/length). Map each hit into the api/web
technique skills' decision tables: a parameter is a *door handle* — what
its values unlock (debug flags, tenant switches, internal hops) is your
analysis, feeding sqlmap/idor/BOLA work rather than closing it.

## What arjun is not

A proof of exploitability or a fuzzer: every hit needs the reachability
argument of *"does this parameter change authorization/behavior?"* before
it is more than a lead. False positives look like real hits (waf batching,
cache keys) — validate each claimant by hand before it reaches your
report, and record method + threads so the run is repeatable.
