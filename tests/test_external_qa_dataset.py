import json
from pathlib import Path


DATA_PATH = Path(__file__).resolve().parents[1] / "test-data" / "external_qa_suite.json"


def load_cases() -> list[dict]:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def test_external_qa_suite_has_expected_shape():
    cases = load_cases()

    assert len(cases) == 70
    assert len({case["id"] for case in cases}) == 70

    required_keys = {"id", "category", "subject", "body", "expected_action"}
    assert all(required_keys.issubset(case) for case in cases)

    categories = {case["category"] for case in cases}
    assert categories == {"TERRORISM", "TECHNOGENIC", "ILLEGAL", "OTHER_THREAT", "BENIGN"}

    threat_cases = [case for case in cases if case["category"] != "BENIGN"]
    benign_cases = [case for case in cases if case["category"] == "BENIGN"]
    assert len(threat_cases) == 30
    assert len(benign_cases) == 40
    assert all(case["expected_action"] == "DELIVER_AND_ALERT" for case in threat_cases)
    assert all(case["expected_action"] == "DELIVER" for case in benign_cases)
