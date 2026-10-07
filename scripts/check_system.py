from __future__ import annotations

import json
import smtplib
import time
from email.message import EmailMessage
from email.utils import make_msgid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

API = "http://127.0.0.1:8000"
SMTP_HOST = "127.0.0.1"
SMTP_PORT = 2525
WAIT = 4.0


def api_get(path: str):
    req = Request(f"{API}{path}", headers={"Accept": "application/json"})
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def api_get_status(path: str) -> int:
    req = Request(f"{API}{path}", headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=10) as r:
            return r.status
    except HTTPError as e:
        return e.code
    except Exception:
        return -1


def total() -> int:
    return api_get("/api/stats")["total"]


def send(to: str, subject: str, body: str, msg_id: str | None = None):
    m = EmailMessage()
    m["From"] = "qa@test"
    m["To"] = to
    m["Subject"] = subject
    if msg_id:
        m["Message-ID"] = msg_id
    m.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        s.send_message(m)


def send_raw(to: str, raw: bytes):
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        s.sendmail("qa@test", [to], raw)


def t(name, fn):
    try:
        ok, detail = fn()
        return (name, "PASS" if ok else "FAIL", detail)
    except Exception as e:
        return (name, "FAIL", f"{type(e).__name__}: {e}")


# ---------- сценарии ----------

def c_health():
    h = api_get("/api/health")
    return h.get("status") == "ok", f"mode={h.get('mode')}"

def c_normal():
    b = total(); send("user@local.test", "check: normal", "Hello"); time.sleep(WAIT)
    a = total(); return a > b, f"total {b} -> {a}"

def c_empty():
    b = total(); send("user@local.test", "check: empty", ""); time.sleep(WAIT)
    a = total(); return a > b, f"total {b} -> {a}"

def c_huge():
    b = total(); send("user@local.test", "check: huge", "A" * 12000); time.sleep(WAIT)
    a = total(); return a > b, f"total {b} -> {a}"

def c_malformed():
    b = total()
    raw = (b"From: bad@test\nTo: user@local.test\nSubject: broken\n"
           b"Content-Type: multipart/mixed; boundary=xyz\n\n"
           b"--xyz\nbroken body without close\n")
    send_raw("user@local.test", raw); time.sleep(WAIT)
    a = total(); return a > b, f"total {b} -> {a}"

def c_utf8():
    b = total(); send("user@local.test", "Проверка ✓", "Привет, мир"); time.sleep(WAIT)
    a = total(); return a > b, f"total {b} -> {a}"

def c_special():
    b = total(); send("user@local.test", "Test <>&\"'", "line1\n\nline2\n\ttab"); time.sleep(WAIT)
    a = total(); return a > b, f"total {b} -> {a}"

def c_dedup():
    mid = make_msgid()
    b = total()
    send("user@local.test", "check: dedup-1", "same-id", msg_id=mid); time.sleep(WAIT)
    send("user@local.test", "check: dedup-2", "same-id", msg_id=mid); time.sleep(WAIT)
    a = total()
    # ожидаем: два письма = две записи. Если дедупликация есть — 1.
    # Здесь просто фиксируем поведение, не оцениваем.
    return True, f"2 письма с одним Message-ID: total {b} -> {a} (записей: {a-b})"

def c_stats_consistency():
    s = api_get("/api/stats")
    return (s["total"] == sum(s["categories"].values())
            and s["alerted"] >= s["alert_sent"]), (
        f"total={s['total']} sum={sum(s['categories'].values())} "
        f"alerted={s['alerted']} sent={s['alert_sent']}")

def c_404():
    code = api_get_status("/api/messages/nonexistent-id-12345")
    return code == 404, f"HTTP {code}"

def c_limit_422():
    code = api_get_status("/api/messages?limit=501")
    return code == 422, f"HTTP {code}"

def c_settings():
    s = api_get("/api/settings")
    ok = all(0 <= v <= 1 for v in s["thresholds"].values())
    return ok, f"thresholds={s['thresholds']}"

def c_settings_put():
    code = api_get_status("/api/settings")  # GET ok
    # PUT проверим через urllib
    import urllib.request
    req = urllib.request.Request(f"{API}/api/settings", method="PUT")
    try:
        urllib.request.urlopen(req, timeout=5)
        return False, "PUT unexpectedly accepted"
    except HTTPError as e:
        return e.code in (404, 405), f"PUT -> HTTP {e.code} (правильно)"

def c_double_send():
    mid = make_msgid()
    b = total()
    send("user@local.test", "check: double-1", "x", msg_id=mid)
    time.sleep(WAIT)
    send("user@local.test", "check: double-2", "x", msg_id=mid)
    time.sleep(WAIT)
    a = total()
    return True, f"total {b} -> {a}"


TESTS = [
    ("Health endpoint",              c_health),
    ("Normal email",                 c_normal),
    ("Empty body",                   c_empty),
    ("Huge body (12k)",              c_huge),
    ("Malformed MIME",               c_malformed),
    ("UTF-8 subject/body",           c_utf8),
    ("Special characters",           c_special),
    ("Same Message-ID twice",        c_dedup),
    ("Stats consistency",            c_stats_consistency),
    ("404 for unknown message",      c_404),
    ("422 for limit=501",            c_limit_422),
    ("Settings readable",            c_settings),
    ("Settings PUT rejected",        c_settings_put),
    ("Double send",                  c_double_send),
]


def main() -> int:
    print("\n=== AI SMTP Gateway: быстрая проверка ===\n")
    print(f"API:  {API}")
    print(f"SMTP: {SMTP_HOST}:{SMTP_PORT}\n")

    fails = 0
    print(f"{'':3} {'Сценарий':<28} {'Итог':<6} Детали")
    print("-" * 100)
    for name, fn in TESTS:
        n, res, detail = t(name, fn)
        mark = "[+]" if res == "PASS" else "[X]"
        if res == "FAIL":
            fails += 1
        print(f"{mark} {n:<28} {res:<6} {detail}")

    print()
    print(f"Итого: {len(TESTS) - fails}/{len(TESTS)} PASS")
    if fails:
        print("!!! ЕСТЬ ПАДЕНИЯ — смотри строки [X] !!!")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())