"""数据保留策略测试。"""
from __future__ import annotations

import json
import os
import time

from p2s.core import retention as R


def _write_scan(d: os.PathLike, scan_id: str, label: str, age_days: float = 0) -> None:
    p = d / f"{scan_id}.json"
    p.write_text(json.dumps({"scan_id": scan_id, "kind": "logs",
                             "target_label": label}), encoding="utf-8")
    if age_days:
        ts = time.time() - age_days * 86400
        os.utime(p, (ts, ts))
    for ext in (".md", ".html"):
        (d / f"{scan_id}{ext}").write_text("x", encoding="utf-8")


def test_dedupe_keeps_newest_and_respects_age(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    # 同一个输入 5 份：2 份老的、3 份新的
    for i in range(2):
        _write_scan(d, f"logs-old{i}", "access.log", age_days=30)
    for i in range(3):
        _write_scan(d, f"logs-new{i}", "access.log", age_days=0)

    r = R.prune_scans(d, keep=3, min_age_days=7, apply=True)
    assert r["removed"] == 2
    left = {p.stem for p in d.glob("*.json")}
    assert left == {"logs-new0", "logs-new1", "logs-new2"}
    # 三种格式一起删
    assert not (d / "logs-old0.md").exists()
    assert not (d / "logs-old0.html").exists()


def test_new_scans_never_removed_by_age(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    for i in range(5):
        _write_scan(d, f"logs-{i}", "same.log", age_days=0)
    r = R.prune_scans(d, keep=1, min_age_days=7, apply=True)
    assert r["removed"] == 0, "7 天内的报告不该被重复清理删除"


def test_max_total_caps_growth(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    for i in range(10):
        _write_scan(d, f"logs-{i:02d}", f"file{i}.log", age_days=1)
    r = R.prune_scans(d, keep=3, min_age_days=7, max_total=4, apply=True)
    assert r["capped"] == 6
    assert len(list(d.glob("*.json"))) == 4


def test_dry_run_changes_nothing(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    for i in range(5):
        _write_scan(d, f"logs-{i}", "x.log", age_days=30)
    before = len(list(d.iterdir()))
    r = R.prune_scans(d, keep=1, min_age_days=7, apply=False)
    assert r["removed"] == 4
    assert len(list(d.iterdir())) == before, "预览模式不应删除任何文件"


def test_prune_uploads_by_age(tmp_path):
    d = tmp_path / "uploads"
    d.mkdir()
    old = d / "old.log"
    old.write_text("x", encoding="utf-8")
    ts = time.time() - 30 * 86400
    os.utime(old, (ts, ts))
    new = d / "new.log"
    new.write_text("x", encoding="utf-8")

    r = R.prune_uploads(d, max_age_days=7, apply=True)
    assert r == {"removed": 1, "scanned": 2, "max_age_days": 7}
    assert new.exists() and not old.exists()


def test_missing_dirs_are_safe(tmp_path):
    assert R.prune_scans(tmp_path / "nope")["removed"] == 0
    assert R.prune_uploads(tmp_path / "nope")["removed"] == 0


def test_corrupt_scan_does_not_crash(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    (d / "broken.json").write_text("{not json", encoding="utf-8")
    _write_scan(d, "logs-ok", "ok.log", age_days=30)
    r = R.prune_scans(d, keep=0, min_age_days=1, apply=True)
    assert r["removed"] >= 1
