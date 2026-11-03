"""Bug-fix contracts: coercions, path containment, key normalization, gates,
pool deadlines. All behavioral (observable return values), no wording."""
import os

from cerberus.schemas import safe_float, safe_int


def test_safe_coercions_never_raise():
    assert safe_int("12-15") == 0
    assert safe_int("unknown") == 0
    assert safe_int(None) == 0
    assert safe_int("42") == 42
    assert safe_int(12.7) == 12
    assert safe_int("7", 99) == 7
    assert safe_int("xx", 99) == 99
    assert safe_float("high") == 0.0
    assert safe_float(None) == 0.0
    assert safe_float("0.8") == 0.8
    assert safe_float(0.5) == 0.5


def test_safe_path_contains_reads(tmp_path, monkeypatch):
    from cerberus.tools.code import _safe_path, grep_files

    # Hermetic CWD: legit reads inside the root work, escapes do not.
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "sub" / "x.txt"
    target.parent.mkdir(parents=True)
    target.write_text("hello\n")
    assert "x.txt:1: hello" in grep_files(regex="hello", include="*", root="sub")
    assert "hello" in grep_files(regex="hello", include="*",
                                  root=str(tmp_path / "sub"))
    for bad in ("/etc/passwd", "../outside",
                os.path.join("sub", "..", "..", "etc", "x")):
        try:
            out = grep_files(regex="x", include="*", root=bad)
            assert out.startswith("ERROR"), bad
        except ValueError:
            pass  # raising is also a contained failure, never content
    # Symlink jailbreak: link inside root pointing outside stays blocked.
    link = tmp_path / "esc"
    try:
        link.symlink_to("/etc")
        try:
            _safe_path(str(link / "passwd"), root=str(tmp_path))
            raise AssertionError("symlink escape not blocked")
        except ValueError:
            pass
    except OSError:
        pass  # symlinks unavailable on this platform


def test_indexer_needs_no_whole_repo_semgrep():
    """Hunters run SAST scans themselves per unit; the indexer must not run
    whole-repo semgrep/opengrep at all (they silently yield zero without
    .git, and duplicate per-unit hunter scans).

    The whole-repo wrappers are gone, so the regression is pinned
    structurally instead of by spy: SAST wrapper candidates are keyed
    ``check_id@path:line``, while the indexer's fast/context
    signals are all static ids ("prefilter", "routes", "secrets", ...).
    A key of the first shape means someone re-added a whole-repo SAST call.
    """
    import re

    import cerberus.pipeline as g

    state = g.indexer_node({"repo": "tests/fixtures/pygoat-sample"})
    assert len(state["files"]) == 3
    ids = [c["id"] for c in state["candidates"]]
    assert "prefilter" in ids
    for cid in ids:
        assert not re.search(r"@.+:\d+$", cid), (
            f"whole-repo SAST candidate reappeared: {cid}")


def test_api_key_gate_uses_the_single_key_env(monkeypatch):
    from cerberus.config import api_key_present
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("CUSTOM_KEY_XYZ", raising=False)
    assert api_key_present({}) is False
    monkeypatch.setenv("API_KEY", "k")
    assert api_key_present({}) is True
    # A yaml key_env pointer (removed surface) can no longer redirect the gate:
    # only API_KEY counts, whatever cfg says.
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.setenv("CUSTOM_KEY_XYZ", "k")
    assert api_key_present({"api_key_env": "CUSTOM_KEY_XYZ"}) is False


def test_validator_batch_missing_id_fail_open(monkeypatch, tmp_path):
    # A batch reply that omits an id must fail that finding open (needs-review
    # + "no validator verdicts") while the verdicts it did return still apply.
    # The double subclasses the real ChatOpenAI: the validator path runs a deep
    # agent, so a duck-typed fake is refused by build_deep_agent and the whole
    # cell would fail open, hiding the contract under test.
    import cerberus.agents.validator as vv
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_openai import ChatOpenAI as RealChat
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("SANDBOX_BACKEND", "local")

    class FakeLLM(RealChat):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            # Structured output is a tool call; content-only JSON is no longer
            # scraped, so this round must use the VerdictBatch channel.
            return ChatResult(generations=[ChatGeneration(
                message=AIMessage(content="", tool_calls=[{
                    "name": "VerdictBatch",
                    "args": {"verdicts": [
                        {"id": "a", "status": "confirmed", "confidence": 0.9,
                         "evidence": "param query:12"}]},
                    "id": "call-1", "type": "tool_call"}]))])

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeLLM)

    def _mk(fid):
        return {"id": fid, "title": fid, "cwe": "CWE-89", "path": "a.py",
                "start_line": 1, "end_line": 1, "snippet": "q",
                "evidence": "concat:1", "status": "needs-review",
                "confidence": 0.5}

    out = vv._validate_unit_batch("u", [_mk("a"), _mk("b")], {}, "", 1)
    by_id = {f["id"]: f for f in out}
    assert by_id["a"]["status"] == "confirmed"
    assert by_id["b"]["status"] == "needs-review"
    # The distinctive marker proves the conservative BALLOT fired (not the
    # cruder "no validator verdicts" fallback), and the note now names which
    # coverage failure it was.
    assert "omitted from batch reply" in by_id["b"]["evidence"]
    assert "no validator verdicts" not in by_id["b"]["evidence"]
