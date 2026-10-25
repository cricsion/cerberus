"""Partitioner prompts: split a codebase into logical units for parallel review."""
from pydantic import BaseModel, Field

from harness.prompts.engine import block

PARTITIONER_SYSTEM = block("partition/partitioner_system")


def build_partition_task(ctx: str, max_units: int) -> str:
    """Assemble the partitioner task prompt around the repo-structure context."""
    return block("partition/task", max_units=max_units, ctx=ctx)


class UnitItem(BaseModel):
    """One logical unit: a business capability, not a directory."""

    name: str = Field(default="", description="Short kebab-case unit name")
    files: list[str] = Field(default_factory=list,
                             description="Exact repo-relative paths in this unit")
    rationale: str = Field(default="", description="One line on why this groups together")


class UnitList(BaseModel):
    """Partition result (object wrapper: backends choke on bare top-level
    arrays)."""

    units: list[UnitItem] = Field(default_factory=list,
                                  description="Logical units covering the repo")
