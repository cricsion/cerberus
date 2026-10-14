---
name: atheris
description: >-
  Run Atheris to fuzz Python code and PROVE exploitability. Use when you have
  a specific suspicious function — a parser, a deserializer, a regex, an
  eval — and a finding is stuck at "needs a crash to confirm". The only tool
  in the stack that produces evidence instead of another lead.
---

# Atheris — Python Fuzzing (the verification half of the loop)

Every other tool here *flags* a pattern. Atheris *proves* behavior: it feeds
generated inputs to a target function and reports a crash, a hang, an
unhandled exception, or a coverage-guided finding. A confirmed crash turns
a `needs-review` finding into a confirmed one — which is where this
harness's real bottleneck is.

## In this environment

- Atheris is **preinstalled, pinned** (pip package in the scan image). Never
  install or upgrade it: the repo is read-only and egress may be denied.
- It is a **verification tool, not a scanner**: it runs against ONE entry
  point you chose, so it is worthless without a hypothesis first (a
  suspicious `pickle.loads`, a hand-rolled parser, an `eval`, a regex on
  user input).
- **Safety**: the fuzz target runs attacker-chosen bytes in-process. Prefer
  fuzzing a *single imported function* in isolation, in a scratch copy under
  `/work` if the unit's imports have side effects, and cap the run with
  `-atheris_runs=` / `timeout`. The repo itself is read-only, so damage can
  only reach your scratch.
- Output discipline: write everything under `/work`, cap with `head`, report
  the crash (function, input shape, stack) — never the raw corpus.

## Writing a fuzz target

```python
# /work/fuzz_target.py
import atheris, sys

@atheris.instrument_func
def target(data: bytes):
    import pickle            # the sink you are testing
    try:
        pickle.loads(data)   # the suspicious call
    except Exception:
        pass                 # "expected" failures are not crashes

atheris.Setup(sys.argv, target)
atheris.Fuzz()
```

Instrument the function under test (`@atheris.instrument_func`) so coverage
guides the fuzzer. Catch the exceptions you consider normal — what is left
crashing is the signal.

API verified against the shipped wheel (3.0.0, the pinned version): the
documented surface is `atheris.Setup`, `atheris.Fuzz`, and
`atheris.instrument_func` / `atheris.instrument_imports` (the latter
instruments imported modules instead of decorated functions). CLI flags
`-runs=`, `-atheris_runs=`, `-artifact_prefix=`, and `max_len` all exist.

## Running it

```bash
python3 /work/fuzz_target.py                       # runs until crash/^C
python3 /work/fuzz_target.py -runs=100000          # bounded run
timeout 100 python3 /work/fuzz_target.py -runs=1000000   # hard wall clock
python3 /work/fuzz_target.py -atheris_runs=50000 -artifact_prefix=/work/crash_
```

## Reading the result

Atheris prints the crashing input as a Python literal and writes the repro
under the artifact prefix. The finding contract entry:

- `title`: "fuzzing crash: <exception type> in <function>"
- `cwe`: the sink's CWE (e.g. CWE-502 deserialization), or CWE-20 when it is
  an unhandled input-validation failure
- `severity`: from the crash — memory corruption / sandbox escape `high`,
  unhandled exception `medium`, hang/DoS `medium`
- `confidence`: 0.9 — a reproduced crash is evidence, not a heuristic
- `evidence`: the reproducer input (shortened), the stack trace, and the
  exact command that produced it
- `snippet`: the sink call

## What atheris is not

Python-only, and it does not find logic bugs that do not crash — an
authorization flaw will not fuzz itself into a signal. Pair it with reading
the code (and the semgrep engines) for what crash-based evidence cannot
reach.
