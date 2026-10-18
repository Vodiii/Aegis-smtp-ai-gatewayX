# AI SMTP Gateway MVP v0.8.12

SMTP security gateway for hackathon MVP.

## Concurrent external QA sender

The external QA script submits messages concurrently instead of waiting for one SMTP transaction to finish before starting the next. The default concurrency is 10 simultaneous SMTP connections to avoid an unnecessarily large burst against the Gateway.

```powershell
python scripts/run_quality_suite.py --data test-data/external_qa_suite.json
```

Tune concurrent submissions explicitly when needed:

```powershell
python scripts/run_quality_suite.py --data test-data/external_qa_suite.json --send-concurrency 20
```

Use `--send-concurrency 1` to restore sequential submission. The script reports SMTP submission time, the measured full-suite wall time, the worker classification span, and per-message latency statistics. By default it waits for the expected final delivery status as well as the classification record. Use `--classification-only` for a classification-only run. The sum of per-message durations may exceed wall time because durations overlap during concurrent/batched processing; it is not the test elapsed time.

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

Первый этап использует единый запрос, возвращающий наличие угрозы и категорию. Основные пакеты проходят через `DEEPSEEK_API_KEY_PRIMARY`. Сомнительные результаты собираются в отдельной очереди и повторно проверяются пакетным запросом через **тот же единственный API-ключ**. По умолчанию очередь ждёт до 0,1 секунды и объединяет до 10 писем.

Очередь первичного этапа собирает до 20 заданий и ждёт не более 250 мс после первого письма. Только письма, которым нужен ИИ, отправляются в DeepSeek пакетами до 10. Два потока обработки позволяют собирать результаты для очереди повторной проверки одновременно из разных первичных пакетов. Ошибка повторного запроса не оставляет оспоренный `BENIGN` без уведомления безопасности: применяется консервативный fallback с ручной проверкой.

A narrow post-AI category policy resolves recurring taxonomy overlaps without issuing another AI request:
- data/photo/chat disclosure or reputation threats take precedence over a generic ILLEGAL label;
- cyber/malware/virus actions are OTHER_THREAT unless an explicit physical technogenic accident/disaster is described;
- a cyber action that explicitly causes a physical infrastructure disaster remains TECHNOGENIC.
- broad/mass attack wording takes precedence over a generic ILLEGAL label when the threatened harm is directed at multiple targets.

Настраивается один ключ DeepSeek:

```env
DEEPSEEK_API_KEY_PRIMARY=
```

Первичная классификация и повторная пакетная проверка используют один ключ. Повторная проверка снижает число отдельных API-запросов по сравнению с одиночной проверкой каждого спорного письма; при этом она всё ещё является отдельным проходом модели и может увеличить задержку отдельного письма.

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

The suite prints classification, routing decision, actual delivery status and AI usage for each message. Timing labels distinguish full test wall time from the sum/average/p50/p95 of overlapping per-message durations. Default mode waits for terminal delivery statuses; use `--classification-only` to omit that wait.


## Risk Gate benchmark
The benchmark contains 150 benign and 40 synthetic threat messages across all four threat categories. It reports FAST/AI routing by benign cohort and fails if any synthetic threat bypasses the AI gate.

Version: v0.8.12

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


## Оптимизации производительности (v0.8.5)

- Переиспользуется постоянный HTTP-клиент DeepSeek с пулом keep-alive соединений.
- Ограничен максимальный объём генерируемого JSON-ответа, чтобы не тратить время на избыточный текст.
- Логарифмы вероятностей символьной модели рассчитываются один раз при загрузке модели.
- Компактные варианты локальных ключевых сигналов предварительно рассчитываются один раз.
- Уточнена обработка явно безопасных контекстов: такие контексты могут отменить отдельный лексический сигнал только при отсутствии признаков прямого намерения, угрожающей фразы и обфускации. Общие исторические и учебные упоминания остаются на пути ИИ.
- Исправлено ложное определение смешения алфавитов для составных слов через дефис, например `HTML-письмо`.

Измерение Risk Engine на внешнем наборе из 70 писем без сетевых вызовов: медиана снизилась примерно с 0,483 мс до 0,312 мс на письмо на текущем тестовом окружении. По 60 повторным измерениям батчей по 70 писем после 20 прогревочных запусков. Это локальный микробенчмарк, а не замер полного времени обработки с DeepSeek.

## Mock emergency-call backend (v0.8.4)

The cybersecurity UI can show a list of mock emergency services next to a threat message and submit a simulated call request. This feature is deliberately mock-only: it has no telephony SDK, does not dial phone numbers, and makes no outbound call request. All displayed numbers use `TEST-*` placeholders.

- `GET /api/emergency-services` — returns the dropdown options (`real_calls_enabled: false`).
- `POST /api/messages/{record_id}/emergency-calls` — records a simulated call for a message classified as a threat. JSON body: `{ "service_id": "police", "requested_by": "operator-1", "notes": "Optional note" }`. `requested_by` and `notes` are optional.
- `GET /api/messages/{record_id}/emergency-calls` — returns the persisted simulation history for that message.

A successful POST returns HTTP 201 and `status: "SIMULATED"`, `provider: "MOCK"`, and `real_call_placed: false`. A non-threat message returns HTTP 409; an unknown message returns 404; an unknown service ID returns 422. Call request records are stored in SQLite and survive application/container restarts as long as the `gateway_data` volume is preserved.

Example request:

```bash
curl -X POST http://localhost:8000/api/messages/REPLACE_WITH_RECORD_ID/emergency-calls \
  -H "Content-Type: application/json" \
  -d '{"service_id":"police","requested_by":"operator-1","notes":"Demo only"}'
```

This is an audit-friendly demonstration stub, not a real emergency-dispatch integration. Before any production telephony integration, service directory, authorization, confirmation, and auditable provider-side delivery semantics must be designed separately.


## v0.8.6 batch classification

Batching controls are configurable in `.env`:

```env
QUEUE_BATCH_MAX_MESSAGES=20
QUEUE_BATCH_WAIT_SECONDS=0.25
DEEPSEEK_BATCH_SIZE=10
```

The batching layer improves aggregate throughput and lowers the number of HTTP calls when there is sufficient traffic. It does not guarantee sub-second latency for a single message: the result still waits for the model's response. See `docs/DEEPSEEK_PROMPTS.md` for the exact current single-message and batch prompts, and `PERFORMANCE_REPORT-v0.8.6.md` for verified checks and limitations.


## v0.8.7 — выборочная проверка результатов пакетного ИИ

- Результаты пакетной классификации получают отдельную метку источника `AI_BATCH` для аудита.
- Ответ `BENIGN` после пакетного запроса повторно проверяется одиночным запросом.
- Ответ `OTHER_THREAT` повторно проверяется одиночным запросом, если Risk Engine уже обнаружил локальные признаки риска.
- Если повторная проверка такого `BENIGN` результата недоступна, письмо не остаётся молча безопасным: оно направляется как `OTHER_THREAT` с отметкой ручной проверки.
- Для одиночной классификации восстановлена схема ответа prompt из v0.8.5, на которой ранее проходил внешний QA 70/70.
- Пакетная обработка остаётся включённой для повышения пропускной способности.

**Важно:** внешний набор из 70 писем для v0.8.7 не запускался с реальным DeepSeek из этой среды. Результат v0.8.6 (62/70) остаётся подтверждённым регрессионным сигналом; повторный live QA обязателен перед принятием новой версии.


## v0.8.10 — исправление категории атаки

- Существующее правило широкой/массовой атаки теперь исправляет не только `ILLEGAL`, но и слишком общую `OTHER_THREAT` на `TERRORISM` при совпадении с имеющимися сигналами массовой атаки.
- Добавлен регрессионный тест на кейс `terrorism_05`.
- Пакетная обработка и API-контракт не менялись.
- Локальная проверка: 95 тестов пройдены; P0-сценарии 4/4.
- Внешний QA v0.8.10 после исправления ещё не выполнялся. Последний результат v0.8.9 — 69/70; единственное несовпадение было по категории `terrorism_05`.

## v0.8.9 — пакетная перепроверка на одном API-ключе

- Основная классификация выполняется пакетами через `DEEPSEEK_API_KEY_PRIMARY`.
- Сомнительные результаты собираются в отдельной очереди, затем одним пакетным запросом перепроверяются с помощью того же ключа.
- Ожидание для набора пакета снижено с 1 секунды до 0,1 секунды; размер повторного пакета — до 10 писем.
- `BENIGN` после первичной AI-классификации перепроверяется независимо от локального score: это важно, так как некоторые пропущенные внешним QA угрозы имели score 0.
- `OTHER_THREAT` повторно проверяется по локальным сигналам/риску и уверенности.
- Если повторная проверка недоступна, спорный `BENIGN` переводится в `OTHER_THREAT` с источником `FALLBACK`, чтобы письмо не осталось без уведомления службы безопасности.
- Если API недоступен на первичном проходе, письмо, которому локальный фильтр требовал ИИ, не должно молча считаться безопасным.
- Текущий контракт API для frontend не меняется.

Внешний QA из 70 писем и реальная задержка DeepSeek для v0.8.9 требуют проверки с рабочим ключом. Цель менее 1 секунды на письмо не считается подтверждённой только за счёт пакетирования.
