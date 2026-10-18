# Mock emergency-call backend API (v0.8.4)

The endpoints below are intentionally mock-only. There is no telephony SDK, provider integration, outbound phone call, or dialing functionality. Every service uses a non-dialable `TEST-*` placeholder number. Call-request actions are persisted to the same SQLite database as the gateway.

## 1. List services

`GET /api/emergency-services`

Example response:

```json
{
  "mode": "MOCK",
  "real_calls_enabled": false,
  "services": [
    {
      "id": "police",
      "name": "Полиция (демо)",
      "number": "TEST-101",
      "description": "Тестовый контакт полиции. Реальный вызов не выполняется.",
      "mock_only": true
    }
  ]
}
```

The actual response contains four demo entries: `police`, `fire_rescue`, `medical_emergency`, and `security_service`.

## 2. Request a simulated call

`POST /api/messages/{record_id}/emergency-calls`

Request body:

```json
{
  "service_id": "police",
  "requested_by": "operator-1",
  "notes": "Demo action"
}
```

Only `service_id` is required. `requested_by` and `notes` are optional.

Success: `201 Created`. The response includes a generated `id`, `status: "SIMULATED"`, `provider: "MOCK"`, `real_call_placed: false`, timestamp, and mock provider reference. This means the user action was recorded; it does not mean a real call was placed.

Errors:

- `404` — message not found.
- `409` — message is not classified as a threat.
- `422` — invalid request or unknown service ID.

## 3. List simulated calls for a message

`GET /api/messages/{record_id}/emergency-calls`

Returns the persisted history for this message. Example shape:

```json
{
  "record_id": "<message-id>",
  "mode": "MOCK",
  "real_calls_enabled": false,
  "items": []
}
```

## Suggested frontend sequence

1. When loading the cybersecurity message view, call `GET /api/emergency-services` and show the returned `services` in the dropdown only for threat messages.
2. After operator selection, send `POST /api/messages/{record_id}/emergency-calls` with `service_id` and optionally `requested_by`/`notes`.
3. Show success as **“Тестовый вызов зарегистрирован; реальный звонок не выполнялся”** and display the returned status `SIMULATED`.
4. Refresh `GET /api/messages/{record_id}/emergency-calls` to show the action log.

Do not display these demo identifiers as real telephone numbers. Before any production integration, add authorization, explicit confirmation, audit requirements, rate limits, and a separately reviewed real-provider design.
