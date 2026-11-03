"""schemas.coerce_findings — the disk-loading boundary for findings JSON.

Regression anchor for the audit crash: `cerberus findings <file> --status …`
raised AttributeError on a findings.json containing a bare string row
(`['evil string', {...}]`), because the CLI pre-filters ran before
sort_findings' own dict check. Boundary coercion makes that unreachable.
"""
from __future__ import annotations

import json

from cerberus.schemas import coerce_findings, structured_items

ROW = {"id": "F-1", "title": "x", "severity": "high", "path": "a.py",
       "start_line": 1, "end_line": 2, "confidence": 0.9, "status": "confirmed"}


def test_coerce_keeps_dict_rows_drops_scalars():
    assert coerce_findings([ROW, "evil string", 3, None, ["nested"]]) == [ROW]


def test_coerce_degrades_non_list_payloads():
    assert coerce_findings(ROW) == []
    assert coerce_findings("x") == []
    assert coerce_findings(None) == []
    assert coerce_findings({"id": "F-1"}) == []


def test_coerce_is_a_view_no_transformation():
    row = dict(ROW, poc={"status": "proven", "receipt": {}})
    out = coerce_findings([row])
    assert out == [row] and out[0] is row


def test_structured_items_still_filters_model_output():
    class _Obj:  # duck-verdict without model_dump
        pass
    assert structured_items({"verdicts": [ROW, "junk", _Obj()]}) == [ROW]
