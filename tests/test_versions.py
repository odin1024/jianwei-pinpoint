import pytest

from p2s.core.versions import Status, classify, parse_version


@pytest.mark.parametrize(
    "raw,expect",
    [
        ("8.5.12", (8, 5, 12, None)),
        ("PHP/8.4.27", (8, 4, 27, None)),
        ("8.3.36-1", (8, 3, 36, "1")),
        ("8.2.35RC1", (8, 2, 35, "RC")),
        ("garbage", None),
        (None, None),
    ],
)
def test_parse_version(raw, expect):
    assert parse_version(raw) == expect


@pytest.mark.parametrize(
    "ver,status",
    [
        ("8.5.12", Status.PATCHED),
        ("8.5.13", Status.PATCHED),
        ("8.5.11", Status.VULNERABLE),
        ("8.4.27", Status.PATCHED),
        ("8.4.26", Status.VULNERABLE),
        ("8.3.36", Status.PATCHED),
        ("8.3.35", Status.VULNERABLE),
        ("8.2.35", Status.PATCHED),
        ("8.2.34", Status.VULNERABLE),
        ("8.1.35", Status.EOL_BACKPORT_AVAILABLE),
        ("7.4.33", Status.EOL_BACKPORT_AVAILABLE),
        ("5.6.40", Status.EOL_UNPATCHABLE),
        ("8.6.0RC4", Status.DEV),
        ("9.0.0", Status.UNKNOWN),
        ("", Status.UNKNOWN),
    ],
)
def test_classify(ver, status):
    v = classify(ver)
    assert v.status == status, f"{ver} -> {v.status} (reason: {v.reason})"


def test_needs_action_semantics():
    assert classify("8.5.11").needs_action is True
    assert classify("8.5.12").needs_action is False
    assert classify("8.1.30").needs_action is True


def test_vulnerable_reason_mentions_baseline():
    v = classify("8.4.26")
    assert "8.4.27" in v.reason
