---
name: binwalk
description: >-
  Run binwalk for firmware/artifact triage: signature scans over a binary
  blob, entropy hints for encrypted regions, and recursive extraction of
  embedded filesystems, archives, headers and certificates. Use when an IoT
  or firmware unit drops an opaque file that `file` cannot fully identify.
  Fully offline.
---

# binwalk — firmware and artifact extraction front door

Binwalk maps *what is inside* an opaque blob: signatures, embedded data,
compressed payloads. Everything downstream (keys, configs, the next layer to
scan) starts from its extraction tree.

## In this environment

- **binwalk 2.3.4** from the ReFirmLabs git tag is preinstalled (the CLI
  self-reports `v2.3.3+cddfede` — the tag carries the current code; the
  pip-level name is cosmetic). It pins **capstone 4.x** with it; never
  upgrade capstone or binwalk at runtime — a capstone 5 resolves to a
  constant binwalk 2.3.x needs and the CLI stops importing.
- Works fully offline on files already inside `/work`.
- Recursive extraction (`-Me`) writes to the blob's working directory — run
  it inside `/work`, never against a unit source path directly.
- Some filesystem formats (squashfs/jffs2) get **signatures reported but no
  full unpack** — the on-image helper (`sasquatch`) is not installed. Carve
  those by the offsets binwalk reports (`dd`) and continue with `file`/
  `strings`/your unit's tooling.

## Running it

```bash
# signature map — the first 30 seconds should always be this
binwalk /work/firmware.bin | head -60

# entropy: solid high-entropy regions are encrypted/compressed; flat zero
# regions are padding or encryption keys hiding as null blocks
binwalk -E /work/firmware.bin

# recursive extraction into /work/firmware.bin.extracted
cd /work && binwalk -Me /work/firmware.bin

# carve just one class by signature offsets from the map above
binwalk --dd=gzip /work/firmware.bin
```

After extraction, walk the tree with `find`, grep for keys/passwords/URLs —
and point the primitive/RE runbooks (gdb, afl) at any binaries you find.

## Reading the output

The signature table is three columns: decimal offset, hex address, signature
(+ jumps/descriptions). Every `DECIMAL` offset is also your `dd` carve
offset. `-E`'s entropy graph pairs with the table: a signature cluster inside
a uniformly high-entropy region is almost always compressed-then-encrypted,
not plaintext.

## What binwalk is not

A filesystem parser for every format, a decompiler, or a scanner of the code
inside what it extracts — it trims the unknown into recognizable pieces and
stops there. A signature hit is evidence of *packaging*, not of
vulnerability; the binaries it yields need the artifact-toolchain runbooks
(gdb, afl, valgrind) before anything is claimed.
