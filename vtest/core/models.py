from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Optional

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class AgentType(Enum):
    UNIT = "Unit"
    SECURITY = "Security"
    STRESS = "Stress"

class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    agent: AgentType
    file_path: str
    line: Optional[int] = None
    category: List[str] = Field(default_factory=lambda: ["General"]) # <-- Safe default
    log: str
    fix_hint: str

class AgentResult(BaseModel):
    agent: AgentType
    findings: List[Finding]
    summary: str
    error: Optional[str] = None