"""Shared structured-output/fail-open helpers used by agent stages."""
import logging

from cerberus.fallback import EMPTY_STRUCTURED, needs_review_verdicts, runner
from cerberus.schemas import structured_items
from langchain_core.exceptions import ModelAuthenticationError


class _Verdict:
    def model_dump(self):
        return {"id": "a"}


class _Parsed:
    verdicts = [_Verdict()]


def test_structured_items_handles_pydantic_dicts_and_plain_dicts():
    assert structured_items({"verdicts": [{"id": "b"}]}) == [{"id": "b"}]
    assert structured_items(_Parsed()) == [{"id": "a"}]


def test_structured_items_never_raises_on_non_iterable_field():
    assert structured_items({"verdicts": 5}) == []
    assert structured_items({"verdicts": None}) == []


def test_needs_review_verdicts_preserve_original_evidence():
    verdicts = needs_review_verdicts(
        [{"id": "a", "status": "needs-review", "evidence": "original"},
         {"id": "b"}],
        "round failed",
    )
    by_id = {v["id"]: v for v in verdicts}
    assert set(by_id) == {"a", "b"}
    assert by_id["a"]["status"] == "needs-review"
    # The helper must not clobber the caller's hunter evidence.
    assert "evidence" not in by_id["a"]
    assert by_id["a"]["fallback_note"] == "round failed"


def test_runner_returns_call_result_and_default():
    assert runner("test", lambda: 1, default="fallback") == 1

    def _boom():
        raise RuntimeError("down")

    seen = []

    class _Log:
        def debug(self, *args):
            seen.append(args)

    out = runner(
        "test", _boom, default=EMPTY_STRUCTURED, logger=_Log())
    assert out == (None, "")
    assert seen


def test_runner_reraises_config_errors():
    def _boom():
        raise ModelAuthenticationError("bad key")

    try:
        runner("test", _boom,
                      logger=logging.getLogger("test"))
    except ModelAuthenticationError:
        pass
    else:  # pragma: no cover - failure path for the branch above
        raise AssertionError("config error was not re-raised")
