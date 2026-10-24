---
name: pwntools
description: >-
  Script exploits with pwntools (the `pwn` python library): process/ELF
  plumbing, cyclic offset hunting, ROP gadget chains, shellcode, and
  format-string primitives against a locally run target. Everything runs
  in-process and offline; crashes become reproducible Python.
---

# pwntools — turn a triaged crash into a working exploit

The other tools find and classify the bug; pwntools builds the input that
demonstrates it, and leaves the demonstration as reviewable Python instead
of a one-shot shell session.

## In this environment

- **pwntools 4.15.0** is preinstalled (`python3` import, `pwn` helper CLI).
  The pinned co-dependencies (capstone 4.x, binwalk 2.3.4) were chosen for
  it: do not pip-install "updates" of pwntools or capstone — the repo is
  read-only and egress may be denied anyway.
- Write scripts under `/work` and run them with the system `python3`; there
  is no TTY to attach debuggers into — the honest interactive loop is
  **process + corefile** (below), not `gdb.attach` (it spawns a terminal
  multiplexer the container does not have).
- Remote tubes (`remote(...)`) only make sense on lanes with granted egress
  against an in-scope host; on the default `--network none` lane, target
  `process()` and `listen()` on localhost.

## Running it

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

elf  = ELF('/work/target')
p    = process(elf.path)

# 1. find the offset that controls RIP
p.sendline(cyclic(256))
p.wait()
core = p.corefile                      # no terminal needed
offset = cyclic_find(core.fault_addr)  # e.g. 72

# 2. assemble a demonstration payload
rop = ROP(elf)
chain = rop.ret2(elf.symbols['win']) if 'win' in elf.symbols else \
        flat(padding, elf.entry)
log.success(f'offset {offset}; payload {len(chain)} bytes')
```

```bash
pwn -h              # helper CLI: pwn cyclic/shellcraft/checksec/extlib
pwn cyclic 200      # pattern to paste anywhere, including into gdb
python3 -c "$(pwn shellcraft -l | grep -E 'sh$')"
```

`checksec` on a target before writing the chain (`pwn checksec ./binary`)
tells you which mitigations (NX/canary/PIE/RELRO) the payload must respect.

## Reading the output

The artifact is the **script** — a colleague must be able to re-run it and
see the same control-flow hijack. The runbook boundary: a `win()`-style
proof or a blind `execve` on a target you own is a demonstration, not a
claim of code execution elsewhere.

## What pwntools is not

It does not find bugs (gdb/valgrind/afl found the one you are exploiting),
it does not fix ASLR semantics for you (its shellcode must match
`context.arch`), and `shellcraft` does not remove the authorization question
about whatever it is pointed at. Exploit scripts belong to your unit's
report only, marked as demonstrations against the local target.
