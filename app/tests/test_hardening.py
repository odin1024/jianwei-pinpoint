"""加固核心逻辑测试（L1 方案 / L1.5 漂移 / 包内容）。"""
from __future__ import annotations

from p2s.core import hardening as H

REPORT = {
    "ini_path": "/etc/php/8.3/fpm/php.ini",
    "ini_sha256": "a" * 64,
    "php_bin": "/usr/bin/php8.3",
    "settings": [
        {"name": "session.upload_progress.enabled", "actual": "1"},
        {"name": "session.use_only_cookies", "actual": "0"},
        {"name": "session.use_strict_mode", "actual": "1"},
        {"name": "display_errors", "actual": "Off"},
    ],
}


def test_plan_only_includes_violations():
    actions = H.plan_actions(REPORT)
    keys = [a["key"] for a in actions]
    assert keys == ["session.upload_progress.enabled", "session.use_only_cookies"]
    assert all(a["action"] == "php.ini.set" for a in actions)


def test_bool_normalization_avoids_false_positives():
    """On/1、Off/0 语义相同，不应被判为待加固。"""
    rep = {
        "settings": [
            {"name": "session.upload_progress.enabled", "actual": "Off"},
            {"name": "session.use_only_cookies", "actual": "1"},
        ]
    }
    assert H.plan_actions(rep) == []


def test_missing_setting_skipped():
    """PHP 不支持的配置项要跳过，而不是生成无效动作。"""
    rep = {"settings": [{"name": "display_errors", "actual": "On"}]}
    keys = [a["key"] for a in H.plan_actions(rep)]
    assert keys == ["display_errors"]


def test_pack_contains_all_files_and_preflight():
    actions = H.plan_actions(REPORT)
    pack = H.build_pack("h1", REPORT, REPORT["ini_path"], actions, token="tok")
    assert set(pack) == {"harden.sh", "rollback.sh", "diff.patch", "manifest.json", "README.txt"}
    sh = pack["harden.sh"]
    # 预检四件套必须在脚本里
    for cue in ("/.dockerenv", "EXPECT_SHA", "ansible", "没有写权限"):
        assert cue in sh
    # 自动回滚路径必须在
    assert "校验未通过，自动回滚" in sh
    # 只做 ini_set，不含任意命令执行
    assert "eval" not in sh.replace("evaluate", "")


def test_pack_quotes_shell_injection():
    """目标路径含单引号/分号时，shell 解析后必须仍是**一个参数**，不能变成多条命令。"""
    import shlex

    evil = "/tmp/x'; rm -rf /; echo '"
    pack = H.build_pack("h1", REPORT, evil, [])
    line = next(ln for ln in pack["harden.sh"].splitlines() if ln.startswith("TARGET="))
    tokens = shlex.split(line[len("TARGET="):])
    assert tokens == [evil], tokens          # 整串仍是一个参数，未被拆成命令


def test_drift_detects_regression():
    baseline = {"session.upload_progress.enabled": "0"}
    rep = {"settings": [{"name": "session.upload_progress.enabled", "actual": "1"}]}
    d = H.drift(rep, baseline)
    assert len(d) == 1 and d[0]["key"] == "session.upload_progress.enabled"


def test_drift_no_baseline():
    assert H.drift(REPORT, None) == []
