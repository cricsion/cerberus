"""Per-repo threat model artifact (THREAT_MODEL.md): scope + prioritization for
hunters/triage. Threats are class-level with closed enums (past vulns/CVEs are
`evidence`), LLM-first over a deterministic floor; every stage degrades, never raises.
"""
from __future__ import annotations

import logging as _logging

# --- public functions -------------------------------------------------------
from .floor import bootstrap_threat, collect_docs, load_threat, measured_facts
from .quality import threat_quality, verify_threat
from .render import render_md, validate_threat_md
from .synthesizer import get_synthesizer_contract
from .swarm import (apply_interview, conduct_interview, enrich_threat,
                    finalize_threat, interview_questions, persist_threat,
                    update_threat_with_findings)
from .util import find_repo_file
from .vulns import parse_vulns_file

# --- public constants -------------------------------------------------------
from .render import (ACTORS, CELL_CAP, FPS_HEADING, IMPACTS, LIKELIHOODS,
                     MACHINE_SECTIONS, NON_EXCLUSION_NOTE, OBSERVED_HEADING,
                     PROPOSALS_HEADING, ROW_CAPS, SECTIONS, STATUSES,
                     THREAT_COLUMNS)
from .swarm import INTERVIEW_QUESTIONS
from .util import CACHE_DIRNAME, CACHE_HEADER, FILENAME
from .vulns import VULNS_BYTES_CAP

from .assemble import _merge_plan
from .floor import _bug_shapes, _vulns_note
from .quality import _map_enum_text, _map_row_enums, _rank_threats
from .render import (_SCOPE_SEMANTICS_RE, _backticked_paths, _coverage_gaps,
                     _parse_entry_points, _parse_threats, _replace_section,
                     _row_enum_gaps, _section)
from .swarm import _bound_json, _llm_structured, _swarm_plan
from .util import _attack_surfaces, _detector_signals, _repo_root

_logger = _logging.getLogger(__name__)
