from __future__ import annotations

import argparse
import smtplib
from email.message import EmailMessage

parser = argparse.ArgumentParser()
parser.add_argument("--to", default="user@local.test")
parser.add_argument("--subject", default="Test message")
parser.add_argument("--body", default="Hello from SMTP AI Gateway")
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=2525)
parser.add_argument("--timeout", type=float, default=60.0, help="SMTP client response timeout in seconds")
args = parser.parse_args()

message = EmailMessage()
message["From"] = "sender@example.com"
message["To"] = args.to
message["Subject"] = args.subject
message.set_content(args.body)

with smtplib.SMTP(args.host, args.port, timeout=args.timeout) as smtp:
    smtp.send_message(message)

print("sent")
