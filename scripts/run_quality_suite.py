from __future__ import annotations

import argparse
import json
import smtplib
import time
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
    parser.add_argument("--data", default="test-data/quality_suite.json")
    parser.add_argument("--wait-seconds", type=float, default=None, help="Maximum wait for async processing; default is sized to the suite")
    args = parser.parse_args()

    cases = json.loads(Path(args.data).read_text(encoding="utf-8"))
    run_id = str(int(time.time()))
    message_ids = {}

    suite_started = time.perf_counter()
    print(f"Running {len(cases)} cases, run={run_id}")
    for case in cases:
        message_id = send_case(case, args.smtp_host, args.smtp_port, run_id, args.smtp_timeout)
        message_ids[message_id] = case
        print(f"  sent {case['id']}")

    # The gateway processes messages asynchronously in the durable queue.
    # Size the default wait to the suite instead of using the old 20s MVP timeout.
    wait_seconds = args.wait_seconds if args.wait_seconds is not None else max(120.0, len(cases) * 4.0)
    deadline = time.time() + wait_seconds
    print(f"Waiting up to {wait_seconds:.0f}s for async processing...")
    results = {}
    while time.time() < deadline and len(results) < len(cases):
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
        if len(results) < len(cases):
            elapsed = time.time() - (deadline - wait_seconds)
            if len(results) and int(elapsed) % 10 < 1:
                print(f"  processed {len(results)}/{len(cases)}")
            time.sleep(0.5)

    print("\nResults")
    print("ID    EXPECTED       ACTUAL         CONF   ACTION               AI     RESULT")
    print("-" * 78)
    failures = 0
    for case in cases:
        message_id = next(mid for mid, c in message_ids.items() if c is case)
        row = results.get(message_id)
        if not row:
            print(f"{case['id']:<5} {case['category']:<14} {'MISSING':<14} {'-':<6} {'-':<20} FAIL")
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
