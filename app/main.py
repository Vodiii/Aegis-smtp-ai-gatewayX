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
from app.milter.gateway import SmtpGatewayHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

config = load_config()
repository = MessageRepository(config.gateway.db_path, config.gateway.data_dir)
classifier = DeepSeekClient(
    config.deepseek_primary_key,
    config.deepseek_secondary_key,
    model=config.gateway.deepseek_model,
    timeout_seconds=config.gateway.deepseek_api_timeout_seconds,
)
policy = PolicyEngine(config.gateway)
processor = EmailProcessor(classifier, policy, repository)
handler = SmtpGatewayHandler(processor, config.gateway)
smtp_controller = Controller(handler, hostname="0.0.0.0", port=2525)

app = FastAPI(title="AI SMTP Gateway", version="0.2.0")
app.include_router(build_router(config, repository))


@app.on_event("startup")
def start_gateway() -> None:
    smtp_controller.start()


@app.on_event("shutdown")
def stop_gateway() -> None:
    smtp_controller.stop()
