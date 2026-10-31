"""一次性票据与计划指纹的测试。"""
from __future__ import annotations

import json
import re

import pytest

from p2s.core import hardening as H

TARGET = "/etc/php/8.3/fpm/php.ini"
HR = {"settings": [
    {"name": "session.upload_progress.enabled", "actual": "1"},
    {"name": "session.use_strict_mode", "actual": "0"},
]}


def _actions() -> list[dict]:
    return H.plan_actions(HR, TARGET)


def test_fingerprint_is_stable() -> None:
    a = H.plan_fingerprint("h1", TARGET, _actions())
    b = H.plan_fingerprint("h1", TARGET, _actions())
    assert a == b and len(a) == 64


@pytest.mark.parametrize("host,target", [("h2", TARGET), ("h1", "/etc/php/8.4/fpm/php.ini")])
def test_fingerprint_changes_with_context(host: str, target: str) -> None:
    base = H.plan_fingerprint("h1", TARGET, _actions())
    assert H.plan_fingerprint(host, target, _actions()) != base


def test_fingerprint_changes_with_actions() -> None:
    acts = _actions()
    base = H.plan_fingerprint("h1", TARGET, acts)
    acts2 = [dict(a) for a in acts]
    acts2[0]["value"] = "9"
    assert H.plan_fingerprint("h1", TARGET, acts2) != base


def test_pack_embeds_ticket_and_hash() -> None:
    acts = _actions()
    ticket = "tk-abcdef123456"
    pack = H.build_pack("h1", HR, TARGET, acts, ticket=ticket)
    sh = pack["harden.sh"]
    assert f"TICKET='{ticket}'" in sh
    want = H.plan_fingerprint("h1", TARGET, acts)
    assert f"PLAN_HASH='{want}'" in sh
    assert "die 21 " in sh, "缺少包内自校验的退出码"


def test_pack_without_ticket_still_works() -> None:
    pack = H.build_pack("h1", HR, TARGET, _actions())
    assert "TICKET=''" in pack["harden.sh"]


def test_receipt_prints_ticket_fields() -> None:
    pack = H.build_pack("h1", HR, TARGET, _actions(), ticket="tk-x")
    sh = pack["harden.sh"]
    assert '"ticket":"%s"' in sh and '"plan_hash":"%s"' in sh


def test_manifest_actions_match_fingerprint() -> None:
    """清单一变，指纹就必须变——这是票据绑定的前提。"""
    acts = _actions()
    pack = H.build_pack("h1", HR, TARGET, acts, ticket="tk-1")
    man = json.loads(pack["manifest.json"])
    keys = [a["key"] for a in man["actions"]]
    assert keys == [a["key"] for a in acts]
    m = re.search(r"^ACT_PAIRS='([^']*)'$", pack["harden.sh"], re.M)
    assert m and m.group(1).count("|") == len(acts) - 1
