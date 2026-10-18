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


def test_expected_delivery_status_maps_actions():
    assert run_quality_suite.expected_delivery_status("DELIVER") == "ORIGINAL_SENT"
    assert run_quality_suite.expected_delivery_status("DELIVER_AND_ALERT") == "ORIGINAL_AND_ALERT_SENT"
    assert run_quality_suite.expected_delivery_status("UNKNOWN") is None


def test_delivery_is_settled_only_when_current_action_is_complete_or_failed():
    assert run_quality_suite.delivery_is_settled({
        "action": "DELIVER_AND_ALERT",
        "forward_status": "ORIGINAL_AND_ALERT_SENT",
    })
    assert run_quality_suite.delivery_is_settled({
        "action": "DELIVER",
        "forward_status": "ORIGINAL_SENT",
    })
    assert not run_quality_suite.delivery_is_settled({
        "action": "DELIVER_AND_ALERT",
        "forward_status": "ORIGINAL_SENT_ALERT_PENDING",
    })
    assert run_quality_suite.delivery_is_settled({
        "action": "DELIVER_AND_ALERT",
        "forward_status": "ORIGINAL_SENT_ALERT_FAILED",
    })


def test_gateway_processing_span_uses_shared_timestamp_window():
    rows = [
        {
            "processing_started_at": "2026-10-18T10:00:00+00:00",
            "processing_finished_at": "2026-10-18T10:00:02+00:00",
        },
        {
            "processing_started_at": "2026-10-18T10:00:01+00:00",
            "processing_finished_at": "2026-10-18T10:00:05+00:00",
        },
    ]
    assert run_quality_suite.gateway_processing_span_seconds(rows) == 5.0


def test_percentile_uses_nearest_rank():
    assert run_quality_suite.percentile([100, 10, 30, 20, 40], 50) == 30
    assert run_quality_suite.percentile([100, 10, 30, 20, 40], 95) == 100
    assert run_quality_suite.percentile([], 95) is None
