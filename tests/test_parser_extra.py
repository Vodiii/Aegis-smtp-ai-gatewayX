from app.infrastructure.parser.email_parser import EmailParser


def test_parse_html_fallback_and_attachment_meta():
    raw = b"""From: sender@example.com\nTo: user@example.com\nSubject: =?utf-8?b?0J/RgNC40LLQtdGC?=\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=abc\n\n--abc\nContent-Type: text/html; charset=utf-8\n\n<html><body><h1>Hello</h1><p>World</p></body></html>\n--abc\nContent-Type: text/plain; name=note.txt\nContent-Disposition: attachment; filename=note.txt\n\nattachment\n--abc--\n"""
    result = EmailParser().parse(raw)
    assert "Hello" in result.text
    assert "World" in result.text
    assert len(result.attachments) == 1
    assert result.attachments[0].filename == "note.txt"


def test_hyphenated_latin_cyrillic_compound_is_not_obfuscation():
    from app.infrastructure.risk.normalizer import normalize

    result = normalize("HTML-письмо без угроз")
    assert result.obfuscation_detected is False
