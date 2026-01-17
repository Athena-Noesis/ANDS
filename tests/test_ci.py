import pytest
from ands.models import ScanReport, ComplianceReport, ComplianceArticle
from ands.ci_engine import CIEngine

@pytest.fixture
def base_report():
    return ScanReport(
        target="https://test.ai",
        reachable=True,
        declared_ands="3.3.3.3.3",
        declared_certification_level="SELF",
        inferred_ands="3.3.3.3.3",
        confidence=1.0,
        evidence=[],
        gaps=[],
        recommendations=[],
        probes=[],
        compliance=ComplianceReport(
            framework="EU AI Act",
            version="2.0",
            overall_score=1.0,
            articles=[ComplianceArticle(id="9", title="Risk", status="compliant", score=1.0)]
        )
    )

def test_compare_no_change(base_report):
    engine = CIEngine()
    deltas = engine.compare(base_report, base_report)
    assert deltas["status"] == "pass"
    assert deltas["axes"]["R"]["delta"] == 0

def test_compare_risk_increase(base_report):
    current = ScanReport(**{k: v for k, v in base_report.__dict__.items()})
    current.inferred_ands = "3.3.3.3.4" # R=4 (increase from 3)

    engine = CIEngine()
    deltas = engine.compare(current, base_report)
    assert deltas["status"] == "block"
    assert "Risk (R) axis increased" in deltas["blocking_issues"][0]

def test_compare_compliance_degrade(base_report):
    current = ScanReport(**{k: v for k, v in base_report.__dict__.items()})
    current.compliance = ComplianceReport(
        framework="EU AI Act",
        version="2.0",
        overall_score=0.5,
        articles=[ComplianceArticle(id="9", title="Risk", status="non_compliant", score=0.0)]
    )

    engine = CIEngine()
    deltas = engine.compare(current, base_report)
    assert deltas["status"] == "block"
    assert "New 'Non-Compliant' status" in deltas["blocking_issues"][0]

def test_compare_agency_spike(base_report):
    current = ScanReport(**{k: v for k, v in base_report.__dict__.items()})
    current.inferred_ands = "3.5.3.3.3" # A=5 (increase from 3)

    engine = CIEngine()
    deltas = engine.compare(current, base_report)
    assert deltas["status"] == "block"
    assert "Agency (A) axis significantly increased" in deltas["blocking_issues"][0]
