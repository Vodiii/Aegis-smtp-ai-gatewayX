# AI SMTP Gateway — MVP v0.4.0

Hackathon MVP: SMTP -> aiosmtpd -> MIME parser -> two-stage DeepSeek classification -> policy -> original delivery + optional alert copy -> SQLite -> FastAPI.

## Two-stage AI classification

1. **Threat Gate**: decides whether the message contains a credible current threat. If not, the message is BENIGN and only goes to the original recipient.
2. **Threat Category**: only when the first stage says `is_threat=true`, classify into exactly one of `TERRORISM`, `TECHNOGENIC`, `ILLEGAL`, `OTHER_THREAT`.

`ILLEGAL` requires a specific unlawful action/intent. A generic personal threat without a distinct unlawful action goes to `OTHER_THREAT`.

A small deterministic signal detector may trigger a focused re-check when the first stage says BENIGN despite very strong threat wording. It does not classify the message by itself.

## Routing

- `BENIGN` / non-threat -> original recipient only.
- Any confirmed threat -> original recipient **and** configured alert mailbox.
- Low confidence threat -> still delivered to both; `review=true` is recorded for the dashboard/analyst.

## Run

```bash
docker compose up --build
```

Original mailbox: http://localhost:8025
Alert mailbox: http://localhost:8026
API: http://localhost:8000/docs
SMTP: localhost:2525

## Reliability hardening

- Transient DeepSeek errors (408/429/5xx) are retried with bounded backoff.
- Primary and secondary API keys are tried independently.
- Invalid/empty AI responses fall back to deterministic classification rather than dropping the SMTP message.
- Fallback classifications are marked for manual review.
- Failed original delivery is recorded as `ORIGINAL_FAILED` and the SMTP gateway returns a temporary `451` so the upstream MTA can retry.
- Alert-copy failure does not block delivery to the original recipient; it is recorded as `ORIGINAL_SENT_ALERT_FAILED`.
- Audit records retain the classification source and policy reason.
