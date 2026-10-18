from certfabric.redaction import REDACTED, Redactor


def test_masks_known_secrets_longest_first():
    redactor = Redactor(["abcd", "abcdefgh"])
    assert redactor.redact("x abcdefgh y abcd") == f"x {REDACTED} y {REDACTED}"


def test_ignores_trivially_short_secrets():
    assert Redactor(["a"]).redact("a cat") == "a cat"


def test_masks_whole_key_block_in_text_and_streamed_lines():
    key = "-----BEGIN PRIVATE KEY-----\nMIIEv\nQIBADAN\n-----END PRIVATE KEY-----"
    assert Redactor().redact(f"before\n{key}\nafter") == f"before\n{REDACTED}\nafter"
    redactor = Redactor()
    streamed = [redactor.redact_line(line) for line in f"before\n{key}\nafter".splitlines()]
    assert [line for line in streamed if line is not None] == ["before", REDACTED, "after"]
