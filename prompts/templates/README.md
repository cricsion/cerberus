# Prompt templates

Prompt copy for `cerberus.prompts` lives here as Markdown files with a small
YAML frontmatter; `cerberus/prompts/engine.py` is the single loader. The
Python modules in `prompts/` compose blocks and weave fenced untrusted data
— this directory is the single place prompt text changes.

## Format

```
---
role: <dirname>               # hunter | validator | triage | threat | partition (must equal the directory)
module: cerberus.prompts.<m>   # provenance pointer to the consuming module
---
<dto — plain Markdown, byte-preserving>
```

One block per file; the loader name is the path under this directory without
`.md` (e.g. `validator/refute_method`).

## Editing rules

- Files end with a single newline that is NOT part of the payload: the
  engine strips exactly one trailing file newline. Trailing blank lines the
  payload itself needs (e.g. the STAGE-4 blocks end in `...\n\n`) live
  inside the payload and are preserved byte-for-byte — mind the difference
  before hitting a formatter that trims trailing whitespace.
- Placeholders use `{{ name }}` only. No Jinja, no `str.format()` — bodies
  are full of literal JSON braces. `engine.block` variables must exactly
  cover the template's placeholders: unresolved or unused names raise.
- Conditional assembly (narrow retry brief, sandbox posture, nonce-fenced
  untrusted blocks) belongs in the Python builders, never here.
- Keep edits byte-compatible: a byte drift in a composed prompt is a
  behavior change for every agent that ships it.
- `UNTRUSTED_CONTEXT_NOTE` (in `prompts/__init__.py`) intentionally stays
  code: it is shared across all agent roles and has no single owning
  directory.
