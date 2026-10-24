---
name: gdb
description: >-
  Run gdb, the GNU debugger. Use when a native binary crashed (or must be
  walked): core-file triage, live breakpoints, disassembly around a suspect
  address, register/memory inspection, and Python-scripted batch sessions.
  Everything is offline in the scan image; there is no interactive UI magic
  (no gef/pwndbg/peda installed) — batch mode is the muscle here.
---

# gdb — crash and memory triage, batch first

The debugger answers "what was the machine doing at the fault?" — the first
question behind any native-code finding. Use it after `file`/`objdump` shaped
the target and before an exploit script is written.

## In this environment

- gdb **13.1 (Debian)** is preinstalled; never install or upgrade it. Python
  scripting inside gdb works (`-ex "python ..."`, `gdb -x script.py`).
- No prettier frontends: **no gef, no pwndbg, no peda**. Everything below is
  vanilla-batch gdb.
- **Batch mode is the default shape**: every `execute` dies after ~120s and
  there is no interactive TTY worth driving. Use `--batch -ex` chains, never
  bare `gdb`.
- ASLR: gdb disables randomization for its children **by default**, so
  addresses repeat across runs. Present this as a reproducibility feature.
- `libc6-dbg` is installed: glibc debug symbols make stack traces and
  valgrind reports readable.

## Running it

```bash
# disassembly + symbol lookup (no run needed)
gdb -q ./binary --batch -ex 'disassemble parse_header' -ex 'info functions'

# core file: the whole crash story at once
gdb -q ./binary /work/core --batch -ex 'bt full' -ex 'info registers' \
    -ex 'info proc mappings'

# live, scripted: break on a known sink, dump, exit
gdb -q --batch -ex 'break write' -ex 'run' -ex 'x/4s $rdi' \
    -ex 'info local' --args ./binary input.txt

# python-scripted surgery
gdb -q ./binary --batch -x /work/inspect.py
```

Backtraces need symbols: rebuild your unit's own code with `gcc -g` when the
report says `??`. `objdump -d` is the no-pipeline alternative for pure
disassembly reading.

## Reading the output

`bt full` is the finding: frame #0 is usually the faulting primitive, the
caller arguments at frame #1+ are the exploit-relevant data. Cross-check
against your unit's source slices (`read_file`, not screenshots of text).

## What gdb is not

A debugger proves execution state for one input. It is not a fuzzer (use
`afl-fuzz` to *generate* crashers — feed those into gdb), not a decompiler
(disassembly only, mind the calling conventions), and not a verdict: a
controlled crash at any address still needs your own reachability argument
before it is more than a lead.
