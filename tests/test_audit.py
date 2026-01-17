import pytest
from ands.models import ScanReport, Evidence
from ands.policy_engine import PolicyEngine

@pytest.fixture
def base_report():
    return ScanReport(
        target="https://test.ai",
        reachable=True,
        declared_ands="3.2.1.2.3",
        declared_certification_level="SELF",
        inferred_ands="3.2.1.2.3",
        confidence=0.8,
        evidence=[],
        gaps=[],
        recommendations=[],
        probes=[]
    )

def test_evaluate_eu_ai_act_compliant(base_report):
    # R=3, M=1, G=2, A=2, C=3
    # Article 9: R <= 3 (3 <= 3) -> Compliant
    # Article 11: G >= 3 (2 >= 3) -> Partial? No, thresholds say G==2 is Partial.
    engine = PolicyEngine()
    compliance = engine.evaluate(base_report, "eu_ai_act")

    art9 = next(a for a in compliance.articles if a.id == "9")
    assert art9.status == "compliant"

    art11 = next(a for a in compliance.articles if a.id == "11")
    assert art11.status == "partial" # G=2

def test_evaluate_eu_ai_act_non_compliant(base_report):
    base_report.inferred_ands = "5.5.5.5.5"
    engine = PolicyEngine()
    compliance = engine.evaluate(base_report, "eu_ai_act")

    art9 = next(a for a in compliance.articles if a.id == "9")
    assert art9.status == "non_compliant" # R=5

    # Article 15: C<=3 and M<=3 and E<=3 (all 5) -> Non-compliant
    art15 = next(a for a in compliance.articles if a.id == "15")
    assert art15.status == "non_compliant"

def test_evaluate_with_evidence_bonus(base_report):
    # Article 14: A <= 3 and G >= 2
    # Let's make it partial: A=4
    base_report.inferred_ands = "3.4.1.2.3" # A=4
    engine = PolicyEngine()
    compliance = engine.evaluate(base_report, "eu_ai_act")
    art14 = next(a for a in compliance.articles if a.id == "14")
    assert art14.status == "partial"

def test_manual_override(base_report):
    overrides = [{"article": "9", "status": "non_compliant", "comment": "Force fail for testing"}]
    engine = PolicyEngine()
    compliance = engine.evaluate(base_report, "eu_ai_act", overrides=overrides)

    art9 = next(a for a in compliance.articles if a.id == "9")
    assert art9.status == "non_compliant"
    assert art9.manual_override is True
