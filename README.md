# AI SMTP Gateway MVP v0.7.3

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
