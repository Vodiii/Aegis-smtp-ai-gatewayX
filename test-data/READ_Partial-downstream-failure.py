////Partial downstream failure////

Что проверяем: падение одного из downstream-каналов (alert упал, original работает).

Тест 2: Partial downstream failure
Дата: 2026-10-08

Действия:
  1. docker stop mailpit-alert
  2. Отправлено письмо с угрозой (захват заложников)

Результат:
  Оригинал получил письмо в mailpit-original
  Alert не доставлен, но поставлен в очередь на retry
  После поднятия контейнера, письмо пошло в 8026
  
Статус: PASS

{
    "id": "662389c3-a383-412f-a2ec-41cf2b7e7934",
    "processed_at": "2026-10-08T12:22:07.370065+00:00",
    "message_id": null,
    "sender": "sender@example.com",
    "subject": "Угроза",
    "category": "TERRORISM",
    "is_threat": true,
    "confidence": 0.95,
    "threat_confidence": 0.95,
    "reason": "Сообщение содержит конкретную угрозу захвата заложников в школе на следующий день, что относится к террористическому насилию.",
    "action": "DELIVER_AND_ALERT",
    "destination": "alerts-terrorism@local.test",
    "review": false,
    "processing_time_ms": 1793,
    "raw_path": "/app/data/messages/662389c3-a383-412f-a2ec-41cf2b7e7934.eml",
    "forward_status": "ORIGINAL_SENT_ALERT_PENDING",
    "forward_error": "ALERT alerts-terrorism@local.test: RETRY [Errno -2] Name or service not known",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "Threat classified as TERRORISM; confidence 0.95 meets threshold 0.70; AI classification. Deliver to original recipients and copy to alert mailbox.",
    "delivery_key": "eee027362de4545f6ae6eac4c7b352f4b7a00127ac7ff89e07cc0e9077346017",
    "risk_score": 0.1984,
    "risk_requires_ai": true,
    "risk_char_probability": 0.9994794829854209,
    "risk_obfuscation_detected": false,
    "risk_reason": "keyword signals: заложник, угроза; char-model threat probability=1.00; combined risk score=0.20; AI required",
    "processing_started_at": "2026-10-08T12:22:05.575941+00:00",
    "processing_finished_at": "2026-10-08T12:22:07.369721+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [
      "Захват заложников в школе",
      "завтра"
    ],
    "risk_keywords": [
      "заложник",
      "угроза"
    ],
    "risk_phrases": []
  }