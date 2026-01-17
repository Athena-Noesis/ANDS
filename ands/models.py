from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

@dataclass
class Evidence:
    source: str
    finding: str
    weight: float = 1.0

@dataclass
class ProbeResult:
    url: str
    method: str
    status: Optional[int]
    headers: Dict[str, str]
    note: str

@dataclass
class ReasoningStep:
    axis: str
    impact: str
    reason: str

@dataclass
class ComplianceArticle:
    id: str
    title: str
    status: str  # compliant, partial, non_compliant
    score: float
    description: Optional[str] = None
    reasoning: Optional[str] = None
    manual_override: bool = False

@dataclass
class ComplianceReport:
    framework: str
    version: str
    overall_score: float
    articles: List[ComplianceArticle]
    auditor_overrides: List[Dict[str, Any]] = None

@dataclass
class ScanReport:
    target: str
    reachable: bool
    declared_ands: Optional[str]
    declared_certification_level: Optional[str]
    inferred_ands: Optional[str]
    confidence: float
    evidence: List[Evidence]
    gaps: List[str]
    recommendations: List[str]
    probes: List[ProbeResult]
    regulations: Dict[str, str] = None
    reasoning: List[ReasoningStep] = None
    compliance: Optional[ComplianceReport] = None
