////Restart after alert delivery////

Что проверяем: после успешной доставки в оба ящика перезапускаем gateway. Обе копии на месте?

1. python scripts\send_test_email.py --subject "Restart-2" --body "Захват заложников в школе"
Письмо пришло только в localhost:8025! В 8026 пусто.
Ошибка распознования ИИ угроз.
category: "BENIGN"
is_threat: false
action: "DELIVER"
destination: null
forward_status: "ORIGINAL_SENT"
reason: "Isolated phrase mentioning a school hostage-taking incident, 
         with no actor, intent, threat, timing, or credible indication 
         of planned or imminent action."
         
Тест 2	«Захват заложников в школе завтра»	TERRORISM
Тест 4  «Захват заложников в школе» (без «завтра»)	BENIGN

Пофиксить логику этому идиоту
Запись из API:
{
    "id": "138853dc-66ba-4848-9aaf-6632e8e8b915",
    "processed_at": "2026-10-08T12:38:40.228774+00:00",
    "message_id": null,
    "sender": "sender@example.com",
    "subject": "Restart-2",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 0.9,
    "threat_confidence": 0.1,
    "reason": "Isolated phrase mentioning a school hostage-taking incident, with no actor, intent, threat, timing, or credible indication of planned or imminent action.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 2584,
    "raw_path": "/app/data/messages/138853dc-66ba-4848-9aaf-6632e8e8b915.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "3deb421931431a7784291098a51f2b6c3dde4889db59a71e5a045a61c12bffb4",
    "risk_score": 0.1488,
    "risk_requires_ai": true,
    "risk_char_probability": 0.9958231051213751,
    "risk_obfuscation_detected": false,
    "risk_reason": "keyword signals: заложник; char-model threat probability=1.00; combined risk score=0.15; AI required",
    "processing_started_at": "2026-10-08T12:38:37.643618+00:00",
    "processing_finished_at": "2026-10-08T12:38:40.228399+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [
      "Захват заложников в школе"
    ],
    "risk_keywords": [
      "заложник"
    ],
    "risk_phrases": []
  }

ТЕПЕРЬ ВСЕ ТАКИ ТЕСТ НА ////Restart after alert delivery////

Тест 4: Restart после alert delivery
Дата: 2026-10-08

Действия:
1. Отправлено письмо «Угроза» (Захват в музее заложников завтра) → TERRORISM, DELIVER_AND_ALERT
2. Проверено: письмо в Mailpit 8025, письмо в Mailpit 8026, запись в /api/messages с forward_status=ORIGINAL_AND_ALERT_SENT
3. docker restart smtp-ai-gateway
4. Проверено: /api/health, /api/messages/{id}, оба Mailpit

Результат:
После docker restart smtp-ai-gateway:
    -/api/health = {"status":"ok","mode":"ENFORCE"}
    -Запись 4beed9cf-4bc7-46ee-967c-0335fabd92ed доступна по API, все поля идентичны
    -Письмо в Mailpit 8025 на месте
    -Письмо в Mailpit 8026 на месте
    
{
    "id": "4beed9cf-4bc7-46ee-967c-0335fabd92ed",
    "processed_at": "2026-10-08T12:50:58.982345+00:00",
    "message_id": null,
    "sender": "sender@example.com",
    "subject": "Угроза",
    "category": "TERRORISM",
    "is_threat": true,
    "confidence": 0.95,
    "threat_confidence": 0.95,
    "reason": "The message warns of a planned hostage-taking in a museum tomorrow, indicating intended terrorist violence.",
    "action": "DELIVER_AND_ALERT",
    "destination": "alerts-terrorism@local.test",
    "review": false,
    "processing_time_ms": 1769,
    "raw_path": "/app/data/messages/4beed9cf-4bc7-46ee-967c-0335fabd92ed.eml",
    "forward_status": "ORIGINAL_AND_ALERT_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "Threat classified as TERRORISM; confidence 0.95 meets threshold 0.70; AI classification. Deliver to original recipients and copy to alert mailbox.",
    "delivery_key": "8a724e3da3b29fe1470958968bd0a7f46ab0114a56303c3695d0fff3610b373c",
    "risk_score": 0.1984,
    "risk_requires_ai": true,
    "risk_char_probability": 0.9998698199256475,
    "risk_obfuscation_detected": false,
    "risk_reason": "keyword signals: заложник, угроза; char-model threat probability=1.00; combined risk score=0.20; AI required",
    "processing_started_at": "2026-10-08T12:50:57.212053+00:00",
    "processing_finished_at": "2026-10-08T12:50:58.981998+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [
      "Захват в музее заложников завтра",
      "заложников"
    ],
    "risk_keywords": [
      "заложник",
      "угроза"
    ],
    "risk_phrases": []
  }