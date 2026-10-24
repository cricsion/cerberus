---
name: afl
description: >-
  Run AFL++, the coverage-guided native fuzzer: build targets through its
  compiler wrappers (afl-gcc-fast / afl-clang-fast), fuzz with afl-fuzz, and
  triage coverage or crashers with afl-showmap / afl-tmin. Use when a native
  parser in your unit should be bombarded with inputs until memory-safety
  bugs fall out. Works fully offline; crashes hand off to gdb/valgrind.
---

# afl — coverage-guided fuzzing of native targets

Coverage feedback turns a stack-based crash hunt from "guess inputs" into
"measure where parsing stops". AFL++ is the image's native-code fuzzer;
atheris is its Python twin (separate skill).

## In this environment

- **afl++ 4.04c** is preinstalled: `afl-fuzz`, builders `afl-gcc`,
  `afl-gcc-fast`, `afl-clang-fast`, helpers `afl-showmap`, `afl-tmin`,
  `afl-plot`. Never install or upgrade any of it.
- gcc/clang are present in the image, so **you are expected to rebuild the
  target** through an afl wrapper before fuzzing. An uninstrumented binary
  only runs under the slow qemu mode (`-Q`), which is for cross-arch
  artifacts, not the normal lane.
- Each `execute` is killed after ~120s and there is no long-lived TTY: run
  `afl-fuzz` with `-V <seconds>` (self-exit) and let the harness's own
  backgrounding carry it, or keep sessions short and resumable
  (`-o` output dir is reused across runs).
- ASAN builds are supported (`afl-clang-fast -fsanitize=address`); cores and
  crash dumps go under `/work`.

## Running it

```bash
# 1. instrument the target (C: swap the compiler)
afl-gcc-fast -g -o /work/target /work/target.c
# make-based projects: make CC=afl-gcc-fast

# 2. seeds — afl-fuzz refuses to start with an empty input dir; one real
#    sample, split into small files, beats a huge corpus
mkdir /work/seeds && printf 'GET /a HTTP/1.1\nHost: x\n' > /work/seeds/s0

# 3. fuzz, self-terminating, non-interactive
AFL_NO_UI=1 afl-fuzz -V 90 -i /work/seeds -o /work/out -- /work/target @@

# 4. triage: per-crash coverage map, then minimize the crasher
afl-showmap -o /dev/null -q -- /work/target /work/out/crashes/id:*
afl-tmin -i /work/out/crashes/id:000000 -o /work/minified -- /work/target @@
```

`@@` is the input-file placeholder; use `-x` with a dictionary instead of
only seed files when the format has known tokens.

## Reading the output

- `out/fuzzer_stats` — exec speed, coverage counts; a target slower than
  ~100 exec/s is your problem to fix (bigger input files are usually why).
- `out/crashes/id:*` — each is a reproducer *file*: run it through gdb
  (`gdb -q ./binary core` on the core it drops, `bt full`) or
  `valgrind --leak-check=full` to name the primitive. A crash with no
  triaged primitive is not a finding yet.

## What afl is not

A fuzzer finds inputs that crash *a specific build*; it does not judge
exploitability, dedupe root causes for you, or say anything about a target
it cannot instrument. Network listeners (`-N`) and fork-server games beyond
`@@` parsing files are out of scope here — taint your conclusions with the
reachability argument your unit requires.
