# Changelog

## v0.8.4 — mock emergency-call backend

- Added `GET /api/emergency-services` for a frontend dropdown with four mock-only service entries.
- Added `POST /api/messages/{message_id}/emergency-calls` to record a simulated call request for a message classified as a threat.
- Added `GET /api/messages/{message_id}/emergency-calls` to retrieve the persisted simulation history.
- Added SQLite persistence for call-action audit records.
- Added explicit `MOCK`, `SIMULATED`, and `real_call_placed: false` indicators; all numbers are `TEST-*` placeholders and cannot be dialed.
- Added API validation for missing messages, non-threat messages, and invalid service IDs.
- Added five tests for catalog response, simulated call creation, persistence across repository restart, non-threat rejection, and request validation.
