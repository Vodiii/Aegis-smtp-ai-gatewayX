////Duplicate SMTP submit////

Что проверяем: что будет, если отправить одно и то же письмо дважды с одинаковым Message-ID. Должна ли система дедуплицировать?

2 раза запускаем сообщение:
python -c "import smtplib; from email.message import EmailMessage; m=EmailMessage(); m['From']='qa@test'; m['To']='user@local.test'; m['Subject']='dedup-1'; m['Message-ID']='<same-id-xyz@test>'; m.set_content('body'); smtplib.SMTP('127.0.0.1',2525,timeout=10).send_message(m)"

По результатам в Mailpit 8025 приходит только 1 письмо с одинаковым ID.

Api message result:
  {
    "id": "5d4e1fcf-25c5-4ce7-a2fd-4456cbe1f96e",
    "processed_at": "2026-10-08T11:56:03.817360+00:00",
    "message_id": "<same-id-xyz@test>",
    "sender": "qa@test",
    "subject": "dedup-1",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 1,
    "threat_confidence": 0,
    "reason": "Message contains no threat content; body is only the placeholder word 'body' and the subject is a deduplication label.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 1287,
    "raw_path": "/app/data/messages/5d4e1fcf-25c5-4ce7-a2fd-4456cbe1f96e.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "a4b85b170d1b82c0a5b4c1629d2e0b87f24e2cc9aa21ba50ee6755137edf541e",
    "risk_score": 0,
    "risk_requires_ai": true,
    "risk_char_probability": 0.8710216975066153,
    "risk_obfuscation_detected": false,
    "risk_reason": "char-model threat probability=0.87; combined risk score=0.00; AI required",
    "processing_started_at": "2026-10-08T11:56:02.529251+00:00",
    "processing_finished_at": "2026-10-08T11:56:03.816951+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [],
    "risk_keywords": [],
    "risk_phrases": []
  },


Тест: Duplicate SMTP submit (три сценария)
Дата: 2026-10-08

Сценарий 1: same-id (одинаковый Message-ID, разное тело)
  Отправлено: 2 письма
  Mailpit 8025: 2 письма
  БД: 2 записи
  delivery_key: разные
  Вывод: дедупликации по Message-ID НЕТ

Сценарий 2: same-body (разный Message-ID, одинаковое тело)
  Отправлено: 2 письма
  Mailpit 8025: 2 письма
  БД: 2 записи
  delivery_key: разные
  Вывод: дедупликации по телу НЕТ

Сценарий 3: same-all (одинаковый Message-ID + одинаковое тело)
  Отправлено: 2 письма
  Mailpit 8025: 1 письмо
  БД: 1 запись
  Вывод: дедупликация СРАБОТАЛА

Общий вывод: система дедуплицирует только полные дубликаты.
delivery_key = хеш(Message-ID + содержимое).


Пометка:
forward_error="Pending deliveries" для ВСЕХ писем, включая доставленные. Это нормально или баг?
Название намекает, что доставка ещё не завершена, хотя forward_status=ORIGINAL_SENT

{
    "id": "e6748cf4-58da-4825-99a6-b4c1ae009f57",
    "processed_at": "2026-10-08T12:08:24.080340+00:00",
    "message_id": "<dedup-same-all@test>",
    "sender": "qa@test",
    "subject": "same-all",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 0.99,
    "threat_confidence": 0,
    "reason": "The message contains only test-like placeholder content with no threatening language, intent, or dangerous action.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 1519,
    "raw_path": "/app/data/messages/e6748cf4-58da-4825-99a6-b4c1ae009f57.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "21d3f31ee8481ffbe7dd9d055707fa2147a2a51e39d54302aa54fc1df99c2efd",
    "risk_score": 0,
    "risk_requires_ai": true,
    "risk_char_probability": 0.8855887117814142,
    "risk_obfuscation_detected": false,
    "risk_reason": "char-model threat probability=0.89; combined risk score=0.00; AI required",
    "processing_started_at": "2026-10-08T12:08:22.560240+00:00",
    "processing_finished_at": "2026-10-08T12:08:24.079278+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [],
    "risk_keywords": [],
    "risk_phrases": []
  },
  {
    "id": "a922bcdc-80d5-4d0c-b4e9-a84efdfa91bc",
    "processed_at": "2026-10-08T12:08:14.249644+00:00",
    "message_id": "<179146129238.3544.8742597772742356995@Labrenis>",
    "sender": "qa@test",
    "subject": "same-body-2",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 1,
    "threat_confidence": 0,
    "reason": "The message body is generic placeholder text with no threatening or dangerous content.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 1282,
    "raw_path": "/app/data/messages/a922bcdc-80d5-4d0c-b4e9-a84efdfa91bc.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "47c25744dbf3353899c59d6d3ca01499e5125040eaa48c80b3decdfb1a63207f",
    "risk_score": 0,
    "risk_requires_ai": true,
    "risk_char_probability": 0.978543663313293,
    "risk_obfuscation_detected": false,
    "risk_reason": "char-model threat probability=0.98; combined risk score=0.00; AI required",
    "processing_started_at": "2026-10-08T12:08:12.966511+00:00",
    "processing_finished_at": "2026-10-08T12:08:14.249197+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [],
    "risk_keywords": [],
    "risk_phrases": []
  },
  {
    "id": "50d5ee36-ebe5-490c-a990-63b8fb85d3e6",
    "processed_at": "2026-10-08T12:08:12.941641+00:00",
    "message_id": "<179146129136.3544.1004869966422738758@Labrenis>",
    "sender": "qa@test",
    "subject": "same-body-1",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 1,
    "threat_confidence": 0,
    "reason": "The message body is generic test content with no threat, harmful intent, or dangerous action.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 1300,
    "raw_path": "/app/data/messages/50d5ee36-ebe5-490c-a990-63b8fb85d3e6.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "a29b00e66b192316f94e49f1b88b57fc6c26f968904a13108dd2a30feef16dc0",
    "risk_score": 0,
    "risk_requires_ai": true,
    "risk_char_probability": 0.978543663313293,
    "risk_obfuscation_detected": false,
    "risk_reason": "char-model threat probability=0.98; combined risk score=0.00; AI required",
    "processing_started_at": "2026-10-08T12:08:11.640098+00:00",
    "processing_finished_at": "2026-10-08T12:08:12.940709+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [],
    "risk_keywords": [],
    "risk_phrases": []
  },
  {
    "id": "68a79dcd-21c3-45b0-82cf-92cbb63da8d2",
    "processed_at": "2026-10-08T12:07:54.293302+00:00",
    "message_id": "<dedup-same-id@test>",
    "sender": "qa@test",
    "subject": "same-id-2",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 1,
    "threat_confidence": 0,
    "reason": "Message body contains only innocuous placeholder text with no threat, dangerous intent, or harmful action.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 1516,
    "raw_path": "/app/data/messages/68a79dcd-21c3-45b0-82cf-92cbb63da8d2.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "7df01a5e14fdf175d56e3762db3e6e2a62c6d8bbd25eb2c1cd5c4d63dfeba5cd",
    "risk_score": 0,
    "risk_requires_ai": true,
    "risk_char_probability": 0.9386935407715281,
    "risk_obfuscation_detected": false,
    "risk_reason": "char-model threat probability=0.94; combined risk score=0.00; AI required",
    "processing_started_at": "2026-10-08T12:07:52.775870+00:00",
    "processing_finished_at": "2026-10-08T12:07:54.292829+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [],
    "risk_keywords": [],
    "risk_phrases": []
  },
  {
    "id": "7d562014-3b23-40f8-9d68-becdda09cb4e",
    "processed_at": "2026-10-08T12:07:52.750824+00:00",
    "message_id": "<dedup-same-id@test>",
    "sender": "qa@test",
    "subject": "same-id-1",
    "category": "BENIGN",
    "is_threat": false,
    "confidence": 1,
    "threat_confidence": 0,
    "reason": "The message contains only benign placeholder/test content with no credible threat or dangerous intent.",
    "action": "DELIVER",
    "destination": null,
    "review": false,
    "processing_time_ms": 1500,
    "raw_path": "/app/data/messages/7d562014-3b23-40f8-9d68-becdda09cb4e.eml",
    "forward_status": "ORIGINAL_SENT",
    "forward_error": "Pending deliveries",
    "classification_source": "AI_UNIFIED",
    "decision_reason": "BENIGN/non-threat classification",
    "delivery_key": "f5e3223b0f5dc5d63c3983dfb3f1a2892c91b5dc8962e1dac47a32847af86115",
    "risk_score": 0,
    "risk_requires_ai": true,
    "risk_char_probability": 0.9386935407715281,
    "risk_obfuscation_detected": false,
    "risk_reason": "char-model threat probability=0.94; combined risk score=0.00; AI required",
    "processing_started_at": "2026-10-08T12:07:51.249673+00:00",
    "processing_finished_at": "2026-10-08T12:07:52.750396+00:00",
    "recipients": [
      "user@local.test"
    ],
    "evidence": [],
    "risk_keywords": [],
    "risk_phrases": []
  }