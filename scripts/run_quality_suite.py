from __future__ import annotations

import argparse
import json
import smtplib
import time
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
    parser.add_argument("--wait-seconds", type=float, default=None, help="Maximum wait for async processing; default is sized to the suite")
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
    print(f"SMTP submission took {send_elapsed:.3f}s. Waiting up to {wait_seconds:.0f}s for async processing...")
    results = {}
    while expected_results and time.time() < deadline and len(results) < expected_results:
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
        if len(results) < expected_results:
            elapsed = time.time() - (deadline - wait_seconds)
            if len(results) and int(elapsed) % 10 < 1:
                print(f"  processed {len(results)}/{expected_results}")
            time.sleep(0.5)

    print("\nResults")
    print("ID    EXPECTED       ACTUAL         CONF   ACTION               AI     RESULT")
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
            print(f"{case_id:<16} {case['category']:<14} {'MISSING':<14} {'-':<6} {'-':<20} FAIL")
            failures += 1
            continue
        actual_category = row.get("category", "?")
        actual_action = row.get("action", "?")
        confidence = float(row.get("confidence", 0.0))
        ok = actual_category == case["category"] and actual_action == case["expected_action"]
        ai_used = "AI" if row.get("risk_requires_ai", True) else "FAST"
        print(
            f"{case['id']:<5} {case['category']:<14} {actual_category:<14} "
            f"{confidence:<6.2f} {actual_action:<20} {ai_used:<6} {'PASS' if ok else 'FAIL'}"
        )
        if not ok:
            failures += 1

    suite_elapsed_ms = (time.perf_counter() - suite_started) * 1000
    processing_times = [int(row.get("processing_time_ms", 0)) for row in results.values() if row.get("processing_time_ms") is not None]
    print(f"\nPassed: {len(cases) - failures}/{len(cases)}")
    print("Timing")
    print(f"  SMTP submission time:                {send_elapsed:.3f} s")
    print(f"  suite wall time (send + wait + API): {suite_elapsed_ms/1000:.3f} s")
    if processing_times:
        print(f"  processing sum (gateway):           {sum(processing_times)/1000:.3f} s")
        print(f"  processing average / message:       {sum(processing_times)/len(processing_times):.1f} ms")
        print(f"  processing min / message:            {min(processing_times)} ms")
        print(f"  processing max / message:            {max(processing_times)} ms")
    missing_count = len(cases) - len(processing_times)
    if missing_count:
        print(f"  messages without timing:             {missing_count}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
