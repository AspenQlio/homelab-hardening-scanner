from enum import Enum
from pydantic import BaseModel
from typing import Optional

class AuditStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"

class AuditFinding(BaseModel):
    module: str
    check_name: str
    status: AuditStatus
    details: str
    remediation: Optional[str] = None
