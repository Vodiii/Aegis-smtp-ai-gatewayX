from app.infrastructure.parser.email_parser import EmailParser


def test_parse_plain_text_email():
    raw = b"""From: sender@example.com\nTo: user@example.com\nSubject: Test\nMessage-ID: <123@test>\nContent-Type: text/plain; charset=utf-8\n\nHello world\n"""
    result = EmailParser().parse(raw)
    assert result.sender == "sender@example.com"
    assert result.recipients == ["user@example.com"]
    assert result.subject == "Test"
    assert result.text == "Hello world"
    assert result.message_id == "<123@test>"
