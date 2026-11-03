"""Per-repo threat model artifact (THREAT_MODEL.md): scope + prioritization for
hunters/triage. Threats are class-level with closed enums (past vulns/CVEs are
`evidence`), LLM-first over a deterministic floor; every stage degrades, never raises.
"""
from __future__ import annotations

import logging as _logging

from .assemble import _merge_plan

# --- public functions -------------------------------------------------------
from .floor import (
                    _bug_shapes,
                    _vulns_note,
                    bootstrap_threat,
                    collect_docs,
                    load_threat,
                    measured_facts,
)
from .quality import _map_enum_text, _map_row_enums, _rank_threats, threat_quality, verify_threat

# --- public constants -------------------------------------------------------
from .render import (
                    _SCOPE_SEMANTICS_RE,
                    ACTORS,
                    CELL_CAP,
                    FPS_HEADING,
                    IMPACTS,
                    LIKELIHOODS,
                    MACHINE_SECTIONS,
                    NON_EXCLUSION_NOTE,
                    OBSERVED_HEADING,
                    PROPOSALS_HEADING,
                    ROW_CAPS,
                    SECTIONS,
                    STATUSES,
                    THREAT_COLUMNS,
                    _backticked_paths,
                    _coverage_gaps,
                    _parse_entry_points,
                    _parse_threats,
                    _replace_section,
                    _row_enum_gaps,
                    _section,
                    render_md,
                    validate_threat_md,
)
from .swarm import (
                    INTERVIEW_QUESTIONS,
                    _bound_json,
                    _llm_structured,
                    _swarm_plan,
                    apply_interview,
                    conduct_interview,
                    enrich_threat,
                    finalize_threat,
                    interview_questions,
                    persist_threat,
                    update_threat_with_findings,
)
from .synthesizer import get_synthesizer_contract
from .util import (
                    CACHE_DIRNAME,
                    CACHE_HEADER,
                    FILENAME,
                    _attack_surfaces,
                    _detector_signals,
                    _repo_root,
                    attach_signal_paths,
                    find_repo_file,
)
from .vulns import VULNS_BYTES_CAP, parse_vulns_file

_logger = _logging.getLogger(__name__)
