from threading import Barrier

from scripts import run_quality_suite


def test_send_cases_concurrently_sends_two_cases_at_the_same_time(monkeypatch):
    barrier = Barrier(2)

    def fake_send_case(case, host, port, run_id, smtp_timeout):
        barrier.wait(timeout=2)
        return f"<{case['id']}@test.local>"

    monkeypatch.setattr(run_quality_suite, "send_case", fake_send_case)
    cases = [{"id": "case_a"}, {"id": "case_b"}]

    sent, errors = run_quality_suite.send_cases_concurrently(
        cases, "localhost", 2525, "test-run", 1.0, max_workers=2
    )

    assert sent == {
        "case_a": "<case_a@test.local>",
        "case_b": "<case_b@test.local>",
    }
    assert errors == {}


def test_send_cases_concurrently_reports_per_case_errors(monkeypatch):
    def fake_send_case(case, host, port, run_id, smtp_timeout):
        if case["id"] == "bad_case":
            raise OSError("SMTP unavailable")
        return f"<{case['id']}@test.local>"

    monkeypatch.setattr(run_quality_suite, "send_case", fake_send_case)
    cases = [{"id": "ok_case"}, {"id": "bad_case"}]

    sent, errors = run_quality_suite.send_cases_concurrently(
        cases, "localhost", 2525, "test-run", 1.0, max_workers=2
    )

    assert sent == {"ok_case": "<ok_case@test.local>"}
    assert "bad_case" in errors
    assert "SMTP unavailable" in errors["bad_case"]
