import smtplib
import time
from email.message import EmailMessage


SMTP_HOST = "localhost"
SMTP_PORT = 2525

SENDER = "sender@example.com"
RECIPIENT = "user@local.test"


TESTS = [
    {
        "name": "BASE",
        "subject": "Захват заложников в школе",
        "body": "Захват заложников в школе.",
    },
    {
        "name": "TOMORROW",
        "subject": "Захват заложников в школе ЗАВТРА",
        "body": "Захват заложников в школе ЗАВТРА.",
    },
    {
        "name": "LOWERCASE_TOMORROW",
        "subject": "Захват заложников в школе завтра",
        "body": "Захват заложников в школе завтра.",
    },
]


def send_test(name: str, subject: str, body: str) -> None:
    print()
    print("=" * 70)
    print(f"TEST: {name}")
    print(f"Subject: {subject}")
    print("=" * 70)

    msg = EmailMessage()

    msg["From"] = SENDER
    msg["To"] = RECIPIENT
    msg["Subject"] = subject

    msg.set_content(body, charset="utf-8")

    try:
        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=15,
        ) as smtp:
            smtp.set_debuglevel(1)

            print("Connecting...")
            smtp.ehlo()

            print("Sending...")
            smtp.send_message(msg)

            print("SUCCESS: message accepted by SMTP Gateway")

    except smtplib.SMTPException as exc:
        print(f"SMTP ERROR: {exc}")
    except OSError as exc:
        print(f"CONNECTION ERROR: {exc}")


def main() -> None:
    print("AI SMTP Gateway manual classification test")
    print(f"SMTP: {SMTP_HOST}:{SMTP_PORT}")
    print(f"From: {SENDER}")
    print(f"To:   {RECIPIENT}")

    for test in TESTS:
        send_test(
            name=test["name"],
            subject=test["subject"],
            body=test["body"],
        )

        # Чтобы логи Gateway было проще читать.
        time.sleep(2)

    print()
    print("=" * 70)
    print("ALL MANUAL TESTS SENT")
    print("=" * 70)
    print()
    print("Теперь смотри логи Gateway.")
    print("Особенно нужны строки:")
    print("  - FAST")
    print("  - AI / DeepSeek")
    print("  - policy")
    print("  - processed")
    print("  - category")
    print("  - action")


if __name__ == "__main__":
    main()
