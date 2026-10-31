"""规则库完整性测试：数量、字段、分类、可执行边界。"""
from __future__ import annotations

import pytest

from p2s.core import hardening as H
from p2s.core import rulebook as R

REQUIRED = ("id", "category", "target", "key", "recommended", "risk", "auto",
            "why", "effects", "verify", "restore")


def test_rule_count_meets_target() -> None:
    """至少 90 条（对外宣称"数量最多"，就得守住这条线）。"""
    assert len(R.ALL) >= 90, f"规则库只有 {len(R.ALL)} 条"


def test_ids_unique() -> None:
    ids = [r.id for r in R.ALL]
    assert len(ids) == len(set(ids)), "规则 ID 有重复"


def test_all_fields_filled() -> None:
    for r in R.ALL:
        d = r.to_dict()
        for f in REQUIRED:
            v = d[f]
            assert v not in (None, ""), f"{r.id} 的 {f} 为空"
        assert len(r.why) >= 15, f"{r.id} 的 why 太短，等于没解释"
        assert len(r.verify) >= 8, f"{r.id} 的 verify 太短，运维无法自证"


def test_risk_values() -> None:
    assert {r.risk for r in R.ALL} <= {"critical", "high", "medium", "low"}


def test_auto_only_for_ini_or_pool() -> None:
    """自动执行只允许改 ini / FPM pool；nginx/systemd 必须人工。"""
    for r in R.ALL:
        if r.auto:
            assert r.target in ("ini", "fpm_pool"), f"{r.id} 标了 auto 但目标是 {r.target}"


def test_categories_consistent() -> None:
    for r in R.ALL:
        assert r.category in R.CATEGORIES


def test_php_85_only_rule_filtered() -> None:
    """fatal_error_backtraces 只在 8.5+ 存在，版本过滤要生效。"""
    for v in ("8.3.6", "8.4.26"):
        keys = [r.key for r in R.for_php_version(v)]
        assert "fatal_error_backtraces" not in keys, f"{v} 不该出现 8.5 专属项"
    keys85 = [r.key for r in R.for_php_version("8.5.12")]
    assert "fatal_error_backtraces" in keys85


def test_stats_shape() -> None:
    st = R.stats()
    assert st["total"] == len(R.ALL)
    assert st["auto"] + st["manual"] == st["total"]
    assert sum(st["by_category"].values()) == st["total"]


def test_plan_keys_all_exist_in_rulebook() -> None:
    """加固流程用的键必须都能在规则库里找到解释，不能有"无出处的键"。"""
    keys = {r.key for r in R.ALL}
    for k in H._PLAN_KEYS:
        assert k in keys, f"{k} 在规则库里没有对应规则"


def test_recommended_comes_from_rulebook() -> None:
    by_key = {r.key: r for r in R.ALL}
    for key, want, risk, why in H.RECOMMENDED:
        assert by_key[key].recommended == want, f"{key} 的建议值与规则库不一致"
        assert by_key[key].why == why
        assert by_key[key].risk == risk


def test_priority_four_in_front() -> None:
    front = [k for k, _, _, _ in H.RECOMMENDED[:4]]
    assert front == ["session.upload_progress.enabled", "session.use_only_cookies",
                     "session.use_strict_mode", "display_errors"]


@pytest.mark.parametrize("cat", list(R.CATEGORIES))
def test_every_category_has_rules(cat: str) -> None:
    assert R.by_category(cat), f"分类 {cat} 为空"
