from __future__ import annotations

import argparse
import smtplib
import time
from email.message import EmailMessage
from email.utils import make_msgid


def send(host: str, port: int, to: str, subject: str, body: str, msg_id: str) -> None:
    m = EmailMessage()
    m["From"] = "qa@test"
    m["To"] = to
    m["Subject"] = subject
    m["Message-ID"] = msg_id
    m.set_content(body)
    with smtplib.SMTP(host, port, timeout=10) as s:
        s.send_message(m)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=2525)
    p.add_argument("--mode", choices=["same-id", "same-body", "same-all"], required=True)
    args = p.parse_args()

    if args.mode == "same-id":
        # одинаковый Message-ID, разное тело
        mid = "<dedup-same-id@test>"
        send(args.host, args.port, "user@local.test", "same-id-1", "body-one", mid)
        time.sleep(1)
        send(args.host, args.port, "user@local.test", "same-id-2", "body-two", mid)
        print("Отправлено 2 письма с Message-ID:", mid)

    elif args.mode == "same-body":
        # разный Message-ID, одинаковое тело
        send(args.host, args.port, "user@local.test", "same-body-1", "identical body", make_msgid())
        time.sleep(1)
        send(args.host, args.port, "user@local.test", "same-body-2", "identical body", make_msgid())
        print("Отправлено 2 письма с одинаковым телом, разными Message-ID")

    elif args.mode == "same-all":
        # всё одинаково
        mid = "<dedup-same-all@test>"
        send(args.host, args.port, "user@local.test", "same-all", "body", mid)
        time.sleep(1)
        send(args.host, args.port, "user@local.test", "same-all", "body", mid)
        print("Отправлено 2 идентичных письма с Message-ID:", mid)


if __name__ == "__main__":
    main()