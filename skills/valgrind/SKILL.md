---
name: valgrind
description: >-
  Run valgrind's memcheck to prove out memory errors in a native target:
  use-after-free, uninitialized reads, buffer overflows, leaks — with origin
  tracking that names the allocation. Use when gdb shows a crash and the
  question is "what class of bug, and who owns the memory?" Fully offline.
---

# valgrind — ground truth for memory errors

Where gdb answers "what was running when it died", valgrind answers "what
memory contract was broken and where the object came from". It is the
authority step behind any memory-safety claim.

## In this environment

- valgrind **3.19.0** is preinstalled with memcheck (default), helgrind and
  DRD (data races), callgrind (hot paths), cachegrind. Never install.
- `libc6-dbg` is present, so stacks are readable; rebuild your unit's code
  with `gcc -g` when its own frames come out bare.
- **It is slow** — memcheck runs 10–50× real time. Feed it one crasher and a
  small fixed input set, never a fuzz loop, and respect the ~120s `execute`
  timeout by keeping inputs minimal (an `afl-tmin`-reduced crasher is the
  ideal patient).
- `--xml` plus a `--log-file` under `/work` is the machine-readable form.

## Running it

```bash
# the standard catch-everything pass
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
         --log-file=/work/valgrind.txt ./binary crasher.input ; \
    grep -A20 'ERROR SUMMARY' /work/valgrind.txt

# race suspicion on threaded code
valgrind --tool=helgrind --log-file=/work/hg.txt ./binary

# which paths are hot (finds the parse loop a fuzzer should push)
valgrind --tool=callgrind ./binary small.input
```

Exit code is **non-zero when errors were found** — a non-zero exit is a
successful diagnostic run, not a crashed tool.

## Reading the output

Every memcheck report is a pair: **where the bad access happened** and
(where relevant) `--track-origins` naming the allocation or the
uninitialized write that created it. Report both. `definitely lost` at small
counts is a leak finding; `possibly lost` inherits your justification.
Errors that repeat per-allocation are one bug, not N findings.

## What valgrind is not

A compiler pass: it intercepts actual execution, so un-reached code is
un-audited. It is not a fuzzer (afl generates the inputs; valgrind grades
them) and it silences *nothing* — every reported error needs the
reachability reason your unit's finding contract demands before it is more
than a lead.
