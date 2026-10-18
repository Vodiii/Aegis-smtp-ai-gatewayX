from __future__ import annotations

import argparse
import json
import smtplib
import time
from datetime import datetime, timezone
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from pathlib import Path
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen


def send_case(case: dict, host: str, port: int, run_id: str, smtp_timeout: float) -> str:
    subject = f"[QA-{run_id}-{case['id']}] {case['subject']}"
    message = EmailMessage()
    message["From"] = "qa@example.com"
    message["To"] = "user@local.test"
    message["Subject"] = case["subject"]
    message["Message-ID"] = f"<qa-{run_id}-{case['id']}@local.test>"
    message["X-QA-Case-ID"] = case["id"]
    message.set_content(case["body"])
    with smtplib.SMTP(host, port, timeout=smtp_timeout) as smtp:
        smtp.send_message(message)
    return message["Message-ID"]


def send_cases_concurrently(
    cases: list[dict],
    host: str,
    port: int,
    run_id: str,
    smtp_timeout: float,
    max_workers: int = 10,
) -> tuple[dict[str, str], dict[str, str]]:
    """Параллельно отправляет тестовые письма через несколько SMTP-соединений.

    Возвращает пары ID теста -> Message-ID и ID теста -> описание ошибки.
    Потоки используются потому, что стандартный smtplib работает синхронно.
    """
    if max_workers < 1:
        raise ValueError("max_workers must be at least 1")

    sent: dict[str, str] = {}
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="qa-smtp-send") as executor:
        futures = {
            executor.submit(send_case, case, host, port, run_id, smtp_timeout): case
            for case in cases
        }
        for future in as_completed(futures):
            case = futures[future]
            try:
                sent[case["id"]] = future.result()
            except Exception as exc:
                errors[case["id"]] = f"{type(exc).__name__}: {exc}"
    return sent, errors



_DELIVERY_SUCCESS_BY_ACTION = {
    "DELIVER": "ORIGINAL_SENT",
    "DELIVER_AND_ALERT": "ORIGINAL_AND_ALERT_SENT",
}
_DELIVERY_TERMINAL_FAILURES = {"ORIGINAL_FAILED", "ORIGINAL_SENT_ALERT_FAILED"}


def expected_delivery_status(action: str) -> str | None:
    """Вернуть ожидаемый итоговый статус доставки для действия шлюза."""
    return _DELIVERY_SUCCESS_BY_ACTION.get(action)


def delivery_is_settled(row: dict) -> bool:
    """Проверить, завершились ли доставки для фактически принятого решения."""
    action = row.get("action")
    status = row.get("forward_status")
    target = expected_delivery_status(action)
    return status in _DELIVERY_TERMINAL_FAILURES or (target is not None and status == target)


def timestamp(value: object) -> datetime | None:
    """Безопасно разобрать ISO-время из API, включая метки с суффиксом Z."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def percentile(values: list[int], p: float) -> int | None:
    """Посчитать процентиль методом ближайшего ранга без внешних библиотек."""
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil((p / 100.0) * len(ordered)) - 1))
    return ordered[index]


def gateway_processing_span_seconds(rows: list[dict]) -> float | None:
    """Рассчитать общий интервал worker-классификации по временным меткам записей."""
    starts = [timestamp(row.get("processing_started_at")) for row in rows]
    finishes = [timestamp(row.get("processing_finished_at")) for row in rows]
    starts = [value for value in starts if value is not None]
    finishes = [value for value in finishes if value is not None]
    if not starts or not finishes:
        return None
    span = (max(finishes) - min(starts)).total_seconds()
    return max(0.0, span)

def fetch_messages(api_url: str) -> list[dict]:
    url = f"{api_url.rstrip('/')}/api/messages?limit=500"
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=10) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"Gateway API returned HTTP {response.status}")
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"Gateway API returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"Gateway API unavailable: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the DeepSeek classification quality suite")
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--smtp-timeout", type=float, default=60.0, help="SMTP client response timeout in seconds")
    parser.add_argument(
        "--send-concurrency",
        type=int,
        default=10,
        help="Maximum number of test emails sent in parallel (default: 10)",
    )
    parser.add_argument("--data", default="test-data/quality_suite.json")
    parser.add_argument("--wait-seconds", type=float, default=None, help="Максимальное ожидание классификации и доставки; по умолчанию зависит от размера набора")
    parser.add_argument("--classification-only", action="store_true", help="Завершить после появления результатов классификации, не дожидаясь подтверждения доставки")
    args = parser.parse_args()

    if args.send_concurrency < 1:
        parser.error("--send-concurrency must be at least 1")

    cases = json.loads(Path(args.data).read_text(encoding="utf-8"))
    run_id = str(int(time.time()))
    cases_by_id = {case["id"]: case for case in cases}

    suite_started = time.perf_counter()
    print(f"Running {len(cases)} cases, run={run_id}")
    print(f"Submitting test emails concurrently (max workers={args.send_concurrency})...")
    send_started = time.perf_counter()
    sent_by_case_id, send_errors = send_cases_concurrently(
        cases,
        args.smtp_host,
        args.smtp_port,
        run_id,
        args.smtp_timeout,
        max_workers=args.send_concurrency,
    )
    send_elapsed = time.perf_counter() - send_started

    for case in cases:
        case_id = case["id"]
        if case_id in sent_by_case_id:
            print(f"  sent {case_id}")
        else:
            print(f"  SEND FAILED {case_id}: {send_errors.get(case_id, 'unknown error')}")

    message_ids = {
        message_id: cases_by_id[case_id]
        for case_id, message_id in sent_by_case_id.items()
    }
    expected_results = len(message_ids)

    # Gateway обрабатывает сообщения асинхронно через постоянную очередь.
    # Время ожидания подбирается под размер набора, а не под старый лимит MVP в 20 секунд.
    wait_seconds = args.wait_seconds if args.wait_seconds is not None else max(120.0, len(cases) * 4.0)
    deadline = time.time() + wait_seconds
    scope = "classification results" if args.classification_only else "classification and delivery confirmation"
    print(f"SMTP submission took {send_elapsed:.3f}s. Waiting up to {wait_seconds:.0f}s for {scope}...")
    wait_started = time.perf_counter()
    last_progress_bucket = -1
    results = {}
    suite_measurement_ms = None
    while expected_results and time.time() < deadline:
        try:
            messages = fetch_messages(args.api_url)
        except Exception as exc:
            print(f"Waiting for API results: {exc}")
            time.sleep(1)
            continue
        for row in messages:
            message_id = row.get("message_id")
            if message_id in message_ids:
                results[message_id] = row

        rows_ready = len(results) >= expected_results
        if rows_ready and not args.classification_only:
            rows_ready = all(delivery_is_settled(results[message_id]) for message_id in message_ids)
        if rows_ready:
            suite_measurement_ms = (time.perf_counter() - suite_started) * 1000
            break

        elapsed = time.perf_counter() - wait_started
        progress_bucket = int(elapsed // 10)
        if results and progress_bucket > last_progress_bucket:
            print(f"  recorded {len(results)}/{expected_results}; delivery states checked" if not args.classification_only else f"  classified {len(results)}/{expected_results}")
            last_progress_bucket = progress_bucket
        time.sleep(0.5)

    print("\nResults")
    print("ID    EXPECTED       ACTUAL         CONF   ACTION               DELIVERY                  AI     RESULT")
    print("-" * 78)
    failures = len(send_errors)
    for case in cases:
        case_id = case["id"]
        if case_id in send_errors:
            print(f"{case_id:<16} {case['category']:<14} {'SEND_FAILED':<14} {'-':<6} {'-':<20} FAIL")
            continue
        message_id = sent_by_case_id.get(case_id)
        row = results.get(message_id) if message_id else None
        if not row:
            print(f"{case_id:<16} {case['category']:<14} {'MISSING':<14} {'-':<6} {'-':<20} {'MISSING':<25} {'-':<6} FAIL")
            failures += 1
            continue
        actual_category = row.get("category", "?")
        actual_action = row.get("action", "?")
        confidence = float(row.get("confidence", 0.0))
        ok = actual_category == case["category"] and actual_action == case["expected_action"]
        ai_used = "AI" if row.get("risk_requires_ai", True) else "FAST"
        expected_forward_status = expected_delivery_status(case["expected_action"])
        actual_forward_status = str(row.get("forward_status", "UNKNOWN"))
        delivery_ok = args.classification_only or actual_forward_status == expected_forward_status
        row_ok = ok and delivery_ok
        print(
            f"{case['id']:<16} {case['category']:<14} {actual_category:<14} "
            f"{confidence:<6.2f} {actual_action:<20} {actual_forward_status:<25} "
            f"{ai_used:<6} {'PASS' if row_ok else 'FAIL'}"
        )
        if not row_ok:
            failures += 1

    suite_elapsed_ms = suite_measurement_ms if suite_measurement_ms is not None else (time.perf_counter() - suite_started) * 1000
    timing_rows = list(results.values())
    processing_times = [int(row.get("processing_time_ms", 0)) for row in timing_rows if row.get("processing_time_ms") is not None]
    delivery_confirmed = sum(
        1 for case in cases
        if case["id"] in sent_by_case_id
        and results.get(sent_by_case_id[case["id"]], {}).get("forward_status") == expected_delivery_status(case["expected_action"])
    )
    print(f"\nPassed: {len(cases) - failures}/{len(cases)}")
    print("Timing (different measurements; do not add them together)")
    print(f"  SMTP submission time:                       {send_elapsed:.3f} s")
    wall_scope = "send through classification only" if args.classification_only else "send through delivery confirmation"
    print(f"  suite end-to-end wall time ({wall_scope}): {suite_elapsed_ms/1000:.3f} s")
    if not args.classification_only:
        print(f"  delivery confirmed for expected action:    {delivery_confirmed}/{len(cases)}")
    span_seconds = gateway_processing_span_seconds(timing_rows)
    if span_seconds is not None:
        print(f"  worker classification span (start to finish timestamps): {span_seconds:.3f} s")
    if processing_times:
        print(f"  sum of per-message durations (overlap):    {sum(processing_times)/1000:.3f} s")
        print(f"  average per-message duration:              {sum(processing_times)/len(processing_times):.1f} ms")
        p50 = percentile(processing_times, 50)
        p95 = percentile(processing_times, 95)
        if p50 is not None:
            print(f"  per-message duration p50:                  {p50} ms")
        if p95 is not None:
            print(f"  per-message duration p95:                  {p95} ms")
        print(f"  per-message duration min:                  {min(processing_times)} ms")
        print(f"  per-message duration max:                  {max(processing_times)} ms")
        print("  note: durations are measured from worker prepare to classification persistence; they exclude queue wait and SMTP delivery, and overlap when emails share a batch.")
    missing_count = len(cases) - len(processing_times)
    if missing_count:
        print(f"  messages without timing:                    {missing_count}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
