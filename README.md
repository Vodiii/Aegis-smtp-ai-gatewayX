# AI SMTP Gateway — MVP v0.2

Minimal hackathon implementation:

`SMTP -> aiosmtpd -> parser -> DeepSeek/fallback -> policy -> SMTP forwarding / alert copy -> SQLite -> FastAPI`

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

SMTP listens on `2525`, API on `8000`.

## Run demo infrastructure

```bash
docker compose up --build
```

Original mailbox UI: http://localhost:8025
Alert mailbox UI: http://localhost:8026
Gateway API: http://localhost:8000/docs
Gateway SMTP: localhost:2525

## Test without DeepSeek

The gateway automatically falls back to a small rule-based classifier when no DeepSeek key is configured. For a confident threat, the message is delivered to the original recipient(s) AND copied to the configured alert mailbox.

```bash
python scripts/send_test_email.py \
  --subject "Обычное письмо" \
  --body "Привет, как дела?"

python scripts/send_test_email.py \
  --subject "Внимание" \
  --body "Завтра произойдет взрыв на заводе."
```

## Important

Real API keys belong only in `.env`. Never commit `.env` or paste production keys into chat/Git.


## Routing semantics

- `BENIGN` -> original recipient(s) only.
- Confident threat -> original recipient(s) AND the category-specific alert mailbox.
- Low-confidence threat -> original recipient(s) with `review=true`.
- If the alert copy fails after the original was delivered, the message is accepted to avoid source-side retransmission and the audit record is marked `ORIGINAL_SENT_ALERT_FAILED`.
