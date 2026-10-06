"""Shared audit result models."""

from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict


class AuditStatus(StrEnum):
    """Possible outcomes for one security check."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"


class AuditFinding(BaseModel):
    """One immutable and actionable security observation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    module: str
    check_name: str
    status: AuditStatus
    details: str
    remediation: str | None = None
