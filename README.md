# AI SMTP Gateway MVP v0.8.3

SMTP security gateway for hackathon MVP.

## Architecture

```text
EMAIL
  ↓
NORMALIZATION
  ↓
┌────────────┬────────────┬────────────┐
│  Keywords  │  Phrases   │  Char ML   │
└────────────┴────────────┴────────────┘
                 ↓
            RISK ENGINE
          ┌──────┴──────┐
          ↓             ↓
       LOW RISK       RISKY
          ↓             ↓
       DELIVER       DeepSeek
                        ↓
                 THREAT + CATEGORY
                        ↓
                     POLICY
                        ↓
               ┌────────┴────────┐
               ↓                 ↓
          DELIVER          DELIVER + ALERT
                                 ↓
                         Security mailbox
```

The gateway never blocks a message solely because it is classified as a threat. A threat message is delivered to the original recipients and copied to the configured security mailbox.

## Fast Risk Engine

The Risk Engine is a conservative pre-AI gate. It may bypass AI only for high-confidence benign context. Suspicious or ambiguous mail stays on the AI path.

The character n-gram model is an auxiliary signal for obfuscation/generalization and never causes ordinary mail to be classified as safe by itself. A separate threat-intent signal prevents generic direct threats from bypassing AI.

A local benchmark is available:

```bash
python scripts/benchmark_risk_gate.py
```

Current benchmark target:

- 150 benign messages;
- 40 synthetic threat messages;
- zero threat messages may bypass AI;
- suspicious-benign cases remain on AI when they contain threat vocabulary.

## DeepSeek

DeepSeek is an implementation of the classifier interface, not a hard dependency of the rest of the gateway design. This allows a future local or enterprise classifier to replace it.

The normal path uses one unified AI request that returns both threat status and category. A second request is used only for a high-signal disagreement (for example, the model says BENIGN while deterministic security signals disagree). This avoids the previous always-on two-stage API sequence while preserving a conservative re-check path.

A narrow post-AI category policy resolves recurring taxonomy overlaps without issuing another AI request:
- data/photo/chat disclosure or reputation threats take precedence over a generic ILLEGAL label;
- cyber/malware/virus actions are OTHER_THREAT unless an explicit physical technogenic accident/disaster is described;
- a cyber action that explicitly causes a physical infrastructure disaster remains TECHNOGENIC.
- broad/mass attack wording takes precedence over a generic ILLEGAL label when the threatened harm is directed at multiple targets.

Two API keys are supported:

```env
DEEPSEEK_API_KEY_PRIMARY=
DEEPSEEK_API_KEY_SECONDARY=
```

Keys are used for fallback/redundancy, not as a way to bypass account-level concurrency limits.

## Run

```bash
docker compose up -d --build
```

API:

```text
http://localhost:8000/docs
```

SMTP Gateway:

```text
localhost:2525
```

Mailpit original:

```text
http://localhost:8025
```

Mailpit security alerts:

```text
http://localhost:8026
```

## Quality suite

The baseline suite contains 15 internal regression cases:

```bash
python scripts/run_quality_suite.py
```

The external regression suite from the tester contains 70 cases: 30 threat cases and 40 benign cases across Russian/English text, obfuscation, news, quotations and metaphors. Run it with:

```bash
python scripts/run_quality_suite.py --data test-data/external_qa_suite.json
```

The suite prints classification, routing decision, AI usage and processing timing for each message, plus total/average/min/max gateway processing time.


## Risk Gate benchmark
The benchmark contains 150 benign and 40 synthetic threat messages across all four threat categories. It reports FAST/AI routing by benign cohort and fails if any synthetic threat bypasses the AI gate.

Version: v0.8.3

## v0.8.2 reliability
SMTP DATA now durably spools the message into SQLite + a fsynced raw file and returns 250 before classification/delivery. A background worker provides crash recovery, durable queue state, per-recipient delivery records, retries, and idempotent enqueue semantics. Delivery is at-least-once across process crashes.


## Quality suite with async queue
The gateway now processes mail asynchronously. `scripts/run_quality_suite.py` therefore sizes its default wait window from the number of cases (minimum 120s). Override with `--wait-seconds` when needed.

Example:
```powershell
python scripts/run_quality_suite.py --data test-data/external_qa_suite.json
```


## v0.8.3 P0 failure-test hardening

The durable queue now has a dedicated failure-scenario regression suite covering: concurrent duplicate enqueue, per-recipient partial failure isolation, stale queue recovery after restart, and the unavoidable SMTP crash window after downstream acceptance. The product semantics are explicitly **at-least-once** across that final crash window; exactly-once delivery cannot be guaranteed by SMTP alone.

Run the local P0 failure tests with:

```bash
python -m pytest -q tests/test_failure_scenarios.py
```

## P0 verification

Run the dedicated failure scenarios without calling DeepSeek:

```bash
python scripts/run_p0_failure_suite.py
```

The suite validates concurrent duplicate enqueue, per-recipient partial failure, stale queue recovery, and the SMTP crash boundary. It intentionally documents the product as **at-least-once** across a crash that occurs after downstream acceptance but before the local `SENT` transaction commits.
