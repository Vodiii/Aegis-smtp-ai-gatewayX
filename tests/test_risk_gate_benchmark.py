from scripts.benchmark_risk_gate import make_cases
from app.domain.models import EmailDocument, GatewaySettings
from app.infrastructure.risk.engine import RiskEngine


def test_benchmark_has_target_shape():
    benign, threats = make_cases()
    assert len(benign) == 150
    assert len(threats) == 40


def test_all_synthetic_threats_require_ai():
    engine = RiskEngine(GatewaySettings())
    _, threats = make_cases()
    for case in threats:
        result = engine.assess(EmailDocument(subject=case["subject"], text=case["body"]))
        assert result.requires_ai is True, case["id"]


def test_benchmark_bypasses_obvious_benign_mail():
    engine = RiskEngine(GatewaySettings())
    benign, _ = make_cases()
    fast = sum(
        not engine.assess(EmailDocument(subject=case["subject"], text=case["body"])).requires_ai
        for case in benign
    )
    assert fast >= 60


def test_benchmark_sends_suspicious_benign_cases_to_ai_more_often():
    engine = RiskEngine(GatewaySettings())
    benign, _ = make_cases()
    suspicious = [case for case in benign if case.get("cohort") == "suspicious-benign"]
    assert suspicious
    ai_count = sum(
        engine.assess(EmailDocument(subject=case["subject"], text=case["body"])).requires_ai
        for case in suspicious
    )
    assert ai_count >= len(suspicious) * 0.5


def test_char_signal_threat_cannot_bypass_ai():
    engine = RiskEngine(GatewaySettings())
    result = engine.assess(EmailDocument(subject="Предупреждение", text="Подготовлена атака с целью вызвать массовый страх и жертвы."))
    assert result.char_probability >= 0.75
    assert result.requires_ai is True
