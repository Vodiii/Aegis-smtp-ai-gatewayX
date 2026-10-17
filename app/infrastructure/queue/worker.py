from __future__ import annotations

import logging
import smtplib
import threading
import time
import uuid
from email import policy
from email.parser import BytesParser
from typing import Any

from app.application.processing_service import EmailProcessor
from app.domain.models import Action, GatewaySettings
from app.infrastructure.database.repository import MessageRepository

LOGGER = logging.getLogger("app.queue")


class DeliveryWorker:
    """Фоновый обработчик классификации и доставки писем.

    SMTP-транзакция сохраняет письмо в SQLite и файловое хранилище, после чего
    возвращает ответ 250. Worker выполняет классификацию и доставку с отдельным
    постоянным состоянием для каждого получателя. При аварийном завершении
    гарантируется повторная обработка, а не строго однократная доставка: SMTP
    не может закрыть окно сбоя между приёмом письма целевым сервером и записью
    локального состояния доставки.
    """

    def __init__(self, repository: MessageRepository, processor: EmailProcessor, settings: GatewaySettings) -> None:
        self.repository = repository
        self.processor = processor
        self.settings = settings
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self.loop_token = settings.gateway_loop_token

    def start(self) -> None:
        if any(thread.is_alive() for thread in self._threads):
            return
        self.repository.recover_stale_jobs(self.settings.queue_stale_seconds)
        self._stop_event.clear()
        worker_count = max(1, int(self.settings.queue_worker_count))
        self._threads = [
            threading.Thread(
                target=self._run,
                args=(index,),
                name=f"delivery-worker-{index + 1}",
                daemon=True,
            )
            for index in range(worker_count)
        ]
        for thread in self._threads:
            thread.start()
        LOGGER.info("Фоновые обработчики доставки запущены: количество=%d", worker_count)

    def stop(self) -> None:
        self._stop_event.set()
        for thread in self._threads:
            thread.join()
        LOGGER.info("Все фоновые обработчики доставки остановлены")

    def _run(self, worker_index: int = 0) -> None:
        while not self._stop_event.is_set():
            first_job = self.repository.claim_next_job()
            if not first_job:
                self._stop_event.wait(self.settings.queue_poll_interval_seconds)
                continue

            jobs = self._collect_batch(first_job)
            try:
                self._process_jobs(jobs)
            except Exception:
                LOGGER.exception("Необработанная ошибка пакета очереди, число заданий=%d", len(jobs))
                for job in jobs:
                    self._handle_job_failure(job, "Unhandled worker batch exception")

    def _collect_batch(self, first_job: dict[str, Any]) -> list[dict[str, Any]]:
        """Собрать до заданного числа писем, не задерживая пакет дольше лимита."""
        jobs = [first_job]
        batch_limit = max(1, self.settings.queue_batch_max_messages)
        wait_limit = max(0.0, self.settings.queue_batch_wait_seconds)
        deadline = time.monotonic() + wait_limit

        while len(jobs) < batch_limit and not self._stop_event.is_set():
            next_job = self.repository.claim_next_job()
            if next_job:
                jobs.append(next_job)
                continue

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # Короткие интервалы опроса позволяют подхватить письма, которые
            # поступили во время ожидания, и быстро завершить неполный пакет.
            self._stop_event.wait(min(0.05, remaining))

        LOGGER.info(
            "Пакет очереди собран: сообщений=%d, размер_пакета=%d, ожидание_мс=%d",
            len(jobs),
            batch_limit,
            int(wait_limit * 1000),
        )
        return jobs

    def _process_job(self, job: dict[str, Any]) -> None:
        """Обработать одно задание через тот же путь, что используется для пакета."""
        self._process_jobs([job])

    def _process_jobs(self, jobs: list[dict[str, Any]]) -> None:
        """Подготовить письма, пакетно классифицировать AI-кандидатов и доставить их."""
        entries: list[dict[str, Any]] = []
        prepared_entries: list[dict[str, Any]] = []

        for job in jobs:
            try:
                raw = self.repository.read_spooled_message(job["raw_path"])
                existing = self.repository.find_by_delivery_key(job["delivery_key"])
                if existing:
                    message_id = existing["id"]
                    result = self.repository.to_processing_result(message_id)
                    if result is None:
                        raise RuntimeError(
                            f"Обработанное сообщение {message_id} не удалось восстановить"
                        )
                    LOGGER.info(
                        "Возобновление задания очереди=%s по сообщению=%s",
                        job["job_id"], message_id,
                    )
                    entries.append({
                        "job": job,
                        "message_id": message_id,
                        "result": result,
                        "prepared": None,
                    })
                else:
                    prepared = self.processor.prepare(raw, delivery_key=job["delivery_key"])
                    entry = {"job": job, "prepared": prepared, "message_id": None, "result": None}
                    entries.append(entry)
                    prepared_entries.append(entry)
            except Exception as exc:
                LOGGER.exception("Не удалось подготовить задание очереди=%s", job["job_id"])
                self._handle_job_failure(job, str(exc))

        if prepared_entries:
            try:
                prepared_messages = [entry["prepared"] for entry in prepared_entries]
                classifications = self.processor.classify_prepared_batch(prepared_messages)
                if len(classifications) != len(prepared_entries):
                    raise RuntimeError("Количество классификаций не совпало с числом писем")
            except Exception as exc:
                LOGGER.exception("Не удалось классифицировать пакет из %d писем", len(prepared_entries))
                for entry in prepared_entries:
                    self._handle_job_failure(entry["job"], f"Batch classification failed: {exc}")
                entries = [entry for entry in entries if entry not in prepared_entries]
            else:
                for entry, classification in zip(prepared_entries, classifications):
                    job = entry["job"]
                    try:
                        message_id, email, result = self.processor.finish_prepared(
                            entry["prepared"], classification
                        )
                        self.repository.ensure_delivery_records(
                            message_id,
                            email.recipients,
                            result.decision.destination
                            if result.decision.action == Action.DELIVER_AND_ALERT
                            and self.settings.mode != "AUDIT"
                            else None,
                        )
                        entry["message_id"] = message_id
                        entry["result"] = result
                    except Exception as exc:
                        LOGGER.exception("Не удалось сохранить результат для задания=%s", job["job_id"])
                        self._handle_job_failure(job, str(exc))
                        entries.remove(entry)

        for entry in entries:
            job = entry["job"]
            message_id = entry["message_id"]
            if not message_id:
                continue
            try:
                self._complete_delivery_job(message_id, job)
            except Exception as exc:
                LOGGER.exception("Ошибка доставки для задания=%s", job["job_id"])
                self._handle_job_failure(job, str(exc))

    def _complete_delivery_job(self, message_id: str, job: dict[str, Any]) -> None:
        """Продолжить независимую доставку оригинала и alert для одного сообщения."""
        self.repository.ensure_delivery_records_from_message(message_id)
        self._deliver_due(message_id, job)

        summary = self.repository.delivery_summary(message_id)
        if summary["pending"] == 0 and summary["retryable"] == 0:
            if summary["final_failed"] == 0:
                self.repository.mark_job_done(job["job_id"])
            else:
                self.repository.dead_letter_job(job["job_id"], "One or more deliveries failed permanently")
        else:
            delay = self._next_delay_for_message(message_id)
            self.repository.retry_job(job["job_id"], delay, self.repository.delivery_error_summary(message_id))

    def _handle_job_failure(self, job: dict[str, Any], error: str) -> None:
        """Поставить задание на повтор или в окончательную очередь ошибок."""
        if int(job["attempts"]) >= self.settings.queue_max_attempts:
            self.repository.dead_letter_job(job["job_id"], error)
        else:
            self.repository.retry_job(
                job["job_id"],
                self._backoff_seconds(job["attempts"]),
                error,
            )

    def _deliver_due(self, message_id: str, job: dict[str, Any]) -> None:
        deliveries = self.repository.due_deliveries(message_id)
        if not deliveries:
            return
        for delivery in deliveries:
            if self._stop_event.is_set():
                return
            try:
                if self._is_loop_copy(delivery["raw_message"]):
                    self.repository.mark_delivery_final_failure(
                        delivery["delivery_id"], "Gateway alert loop marker detected"
                    )
                    continue
                self._send_one(
                    job["sender"],
                    delivery["recipient"],
                    delivery["raw_message"],
                    delivery["host"],
                    delivery["port"],
                )
                self.repository.mark_delivery_sent(delivery["delivery_id"])
            except Exception as exc:
                retryable = self._is_retryable_smtp_error(exc)
                if retryable:
                    next_attempt = int(delivery["attempts"]) + 1
                    if next_attempt >= self.settings.delivery_max_attempts:
                        self.repository.mark_delivery_final_failure(delivery["delivery_id"], str(exc))
                    else:
                        self.repository.mark_delivery_retry(
                            delivery["delivery_id"],
                            self._backoff_seconds(next_attempt, base=self.settings.delivery_retry_base_seconds),
                            str(exc),
                        )
                else:
                    self.repository.mark_delivery_final_failure(delivery["delivery_id"], str(exc))
                LOGGER.exception(
                    "Delivery failed message=%s delivery=%s recipient=%s retryable=%s",
                    message_id,
                    delivery["delivery_id"],
                    delivery["recipient"],
                    retryable,
                )
        self.repository.refresh_forward_status(message_id)

    def _send_one(self, mail_from: str, recipient: str, raw_message: bytes, host: str, port: int) -> None:
        with smtplib.SMTP(host=host, port=port, timeout=self.settings.smtp_timeout_seconds) as smtp:
            failures = smtp.sendmail(mail_from, [recipient], raw_message)
            if failures:
                code = next(iter(failures.values()))[0] if failures else None
                error = next(iter(failures.values()))[1] if failures else failures
                exc = smtplib.SMTPResponseException(code or 550, str(error))
                raise exc

    @staticmethod
    def _is_retryable_smtp_error(exc: Exception) -> bool:
        if isinstance(exc, smtplib.SMTPResponseException):
            return 400 <= int(exc.smtp_code) < 500
        if isinstance(exc, (TimeoutError, OSError, ConnectionError, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError)):
            return True
        return False

    def _backoff_seconds(self, attempts: int, base: float | None = None) -> float:
        base_value = self.settings.queue_retry_base_seconds if base is None else base
        delay = base_value * (2 ** max(0, attempts - 1))
        return min(delay, self.settings.queue_retry_max_seconds)

    def _next_delay_for_message(self, message_id: str) -> float:
        values = self.repository.next_delivery_delays(message_id)
        if not values:
            return self.settings.queue_retry_base_seconds
        return min(values)

    def _is_loop_copy(self, raw_message: bytes) -> bool:
        if not self.loop_token:
            return False
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
        return message.get("X-AI-SMTP-Gateway-Alert") == "1" and message.get("X-AI-SMTP-Gateway-Token") == self.loop_token
