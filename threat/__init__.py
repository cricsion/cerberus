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
from .swarm import (apply_interview, conduct_interview, enrich_threat,
                    finalize_threat, interview_questions, persist_threat,
                    update_threat_with_findings)
from .util import find_repo_file, threat_enabled
from .vulns import parse_vulns_file

# --- public constants -------------------------------------------------------
from .floor import (DOC_CHARS_PER_FILE, DOC_FILES_CAP, DOC_GLOBS,
                    DOC_TOTAL_CAP)
from .quality import IMPACT_RANK, LIKELIHOOD_RANK
from .render import (ACTORS, CELL_CAP, FPS_HEADING, IMPACTS, LIKELIHOODS,
                     MACHINE_SECTIONS, NON_EXCLUSION_NOTE, OBSERVED_HEADING,
                     PROPOSALS_HEADING, ROW_CAPS, SECTIONS, STATUSES,
                     THREAT_COLUMNS)
from .swarm import INTERVIEW_QUESTIONS
from .util import CACHE_DIRNAME, CACHE_HEADER, FILENAME
from .vulns import VULNS_BYTES_CAP, VULNS_FIELD_CAP, VULNS_ROW_CAP

# --- test-compatibility private surface ------------------------------------
# NOT an API; patch `harness.threat.swarm._llm_structured`, not the re-export.
from .assemble import _merge_plan
from .floor import (_bug_shapes, _empty_threats_table, _measured_blocks,
                    _provenance, _vulns_note)
from .quality import (_ACTOR_PHRASES, _CLOSES_PHRASES, _EFFORT_PHRASES,
                      _ENUM_DEFAULTS, _ENUM_PHRASES, _IMPACT_PHRASES,
                      _LIKELIHOOD_PHRASES, _STATUS_PHRASES, _map_enum_text,
                      _map_row_enums, _norm_enums, _rank_threats)
from .render import (_SCOPE_SEMANTICS_RE, _backticked_paths, _cell,
                     _clean_llm_text, _coverage_gaps, _mask_fences,
                     _md_escape_cell, _parse_entry_points, _parse_threats,
                     _replace_section, _row_enum_gaps, _section, _table_rows)
from .swarm import (_bound_json, _history_text, _json_default, _llm_structured,
                    _llm_text, _model_dump, _swarm_history,
                    _swarm_plan, _swarm_research, _synth_task, _threat_mk,
                    _threat_timeout)
from .util import (_GIT_SAFE_OPTS, _SURFACE_FAMILY, _as_bool, _attack_surfaces,
                   _detector_signals, _repo_root)
from .vulns import (_vuln_row, _vulns_from_csv, _vulns_from_json,
                    _vulns_from_markdown)

_logger = _logging.getLogger(__name__)
