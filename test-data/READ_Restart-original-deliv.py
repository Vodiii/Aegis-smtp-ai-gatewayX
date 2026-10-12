////Restart after original delivery////

Что проверяем: после успешной доставки в original перезапускаем gateway. Письмо остаётся в Mailpit? Запись в БД консистентна?

Тест 3: Restart после original delivery
Дата: 2026-10-08

Действия:
  1. Отправлено письмо Restart-1 (BENIGN, DELIVER)
  2. Проверено: письмо в Mailpit 8025, запись в /api/messages
  3. docker restart smtp-ai-gateway
  4. Проверено: /api/health, /api/messages?limit=5

Результат:
  - /api/health = {"status":"ok","mode":"ENFORCE"} после рестарта
  - Запись сохранилась полностью: id, processed_at, forward_status,
    delivery_key, raw_path — идентичны
  - Письмо в Mailpit 8025 на месте
  - SQLite не потеряла данные
Вывод: система персистентна. Рестарт gateway не влияет на уже обработанные записи.
Статус: PASS

{
    "id": "626b353d-e784-4bcc-84ef-a614d9a2f8e2",
    "processed_at": "2026-10-08T12:29:09.500235+00:00",
    "message_id": null,
    "sender": "sender@example.com",
    "subject": "Restart-1",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 1,
    "threat_confidence": 0,
    "reason": "The message contains no threat, dangerous intent, or credible harmful action; it is an ordinary message.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 1493,
    "raw_path": "/app/data/messages/626b353d-e784-4bcc-84ef-a614d9a2f8e2.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "5bfd4e4ed16dcf0acd9aacecbddfdeb04bb7418113117bbf12c11407c052066c",
    "risk_score": 0,
    "risk_requires_ai": true,
    "risk_char_probability": 0.9858016888878168,
    "risk_obfuscation_detected": false,
    "risk_reason": "char-model threat probability=0.99; combined risk score=0.00; AI required",
    "processing_started_at": "2026-10-08T12:29:08.006074+00:00",
    "processing_finished_at": "2026-10-08T12:29:09.499767+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [],
    "risk_keywords": [],
    "risk_phrases": []
}