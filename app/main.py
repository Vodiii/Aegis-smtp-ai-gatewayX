from __future__ import annotations

import logging

from aiosmtpd.controller import Controller
from fastapi import FastAPI

from app.api.routes import build_router
from app.application.policy import PolicyEngine
from app.application.processing_service import EmailProcessor
from app.infrastructure.config import load_config
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.deepseek.client import DeepSeekClient
from app.infrastructure.risk.engine import RiskEngine
from app.gateway import SmtpGatewayHandler
from app.infrastructure.queue.worker import DeliveryWorker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

config = load_config()
repository = MessageRepository(config.gateway.db_path, config.gateway.data_dir)
repository.configure_delivery_endpoints(config.gateway)
classifier = DeepSeekClient(
    config.deepseek_primary_key,
    config.deepseek_secondary_key,
    model=config.gateway.deepseek_model,
    timeout_seconds=config.gateway.deepseek_api_timeout_seconds,
    max_retries=config.gateway.deepseek_max_retries,
    retry_backoff_seconds=config.gateway.deepseek_retry_backoff_seconds,
)
policy = PolicyEngine(config.gateway)
risk_engine = RiskEngine(config.gateway)
processor = EmailProcessor(classifier, policy, repository, risk_engine)
handler = SmtpGatewayHandler(processor, config.gateway)
worker = DeliveryWorker(repository, processor, config.gateway)
smtp_controller = Controller(
    handler,
    hostname="0.0.0.0",
    port=2525,
    data_size_limit=config.gateway.max_message_size_bytes,
    enable_SMTPUTF8=True,
)

app = FastAPI(title="AI SMTP Gateway", version="0.8.2")
app.include_router(build_router(config, repository))


@app.on_event("startup")
def start_gateway() -> None:
    worker.start()
    smtp_controller.start()


@app.on_event("shutdown")
def stop_gateway() -> None:
    smtp_controller.stop()
    worker.stop()
