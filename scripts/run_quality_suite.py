from __future__ import annotations

import argparse
import json
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen


def send_case(case: dict, host: str, port: int, run_id: str) -> str:
    subject = f"[QA-{run_id}-{case['id']}] {case['subject']}"
    message = EmailMessage()
    message["From"] = "qa@example.com"
    message["To"] = "user@local.test"
    message["Subject"] = subject
    message.set_content(case["body"])
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.send_message(message)
    return subject


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
    parser.add_argument("--data", default="test-data/quality_suite.json")
    parser.add_argument("--wait-seconds", type=float, default=20.0)
    args = parser.parse_args()

    cases = json.loads(Path(args.data).read_text(encoding="utf-8"))
    run_id = str(int(time.time()))
    subjects = {}

    print(f"Running {len(cases)} cases, run={run_id}")
    for case in cases:
        subject = send_case(case, args.smtp_host, args.smtp_port, run_id)
        subjects[subject] = case
        print(f"  sent {case['id']}")

    deadline = time.time() + args.wait_seconds
    results = {}
    while time.time() < deadline and len(results) < len(cases):
        try:
            messages = fetch_messages(args.api_url)
        except Exception as exc:
            print(f"Waiting for API results: {exc}")
            time.sleep(1)
            continue
        for row in messages:
            subject = row.get("subject", "")
            if subject in subjects:
                results[subject] = row
        if len(results) < len(cases):
            time.sleep(0.5)

    print("\nResults")
    print("ID    EXPECTED       ACTUAL         CONF   ACTION               RESULT")
    print("-" * 78)
    failures = 0
    for case in cases:
        subject = next(s for s, c in subjects.items() if c is case)
        row = results.get(subject)
        if not row:
            print(f"{case['id']:<5} {case['category']:<14} {'MISSING':<14} {'-':<6} {'-':<20} FAIL")
            failures += 1
            continue
        actual_category = row.get("category", "?")
        actual_action = row.get("action", "?")
        confidence = float(row.get("confidence", 0.0))
        ok = actual_category == case["category"] and actual_action == case["expected_action"]
        print(
            f"{case['id']:<5} {case['category']:<14} {actual_category:<14} "
            f"{confidence:<6.2f} {actual_action:<20} {'PASS' if ok else 'FAIL'}"
        )
        if not ok:
            failures += 1

    print(f"\nPassed: {len(cases) - failures}/{len(cases)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
