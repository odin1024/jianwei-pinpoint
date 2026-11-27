"""资产存储后端（SQLite）的测试。

评审报告 R-12：「资产存储是 JSON 文件 —— 数千条资产后并发写与查询都吃力，
换 SQLite」。本文件守住换完之后的行为不跑偏。

要守住的四件事
--------------
1. **接口语义不变** —— `_load_assets()` / `_save_assets()` 的行为与原 JSON 实现一致；
2. **自动迁移** —— 旧的 assets.json 能自动导入，且**原文件保留**（可人工回退）；
3. **可用性优先** —— SQLite 出问题时自动回退 JSON，平台不因存储故障整体不可用；
4. **脱敏口径不变** —— 落盘前仍要脱敏自由文本，攻击载荷不明文留在磁盘上。
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from p2s.console.asset_store import AssetStore  # noqa: E402


def _asset(host: str, **kw) -> dict:
    d = {"host": host, "device_type": "linux_server", "exposure": "exposed",
         "evidence": ["X-Powered-By: PHP/8.2.12"], "risk": "critical"}
    d.update(kw)
    return d


# ---------------------------------------------------------------- 基础读写
def test_save_then_load_roundtrip(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    items = [_asset("10.0.0.1"), _asset("10.0.0.2", vendor="Canonical")]
    store.save(items)
    out = store.load()
    assert len(out) == 2
    assert {a["host"] for a in out} == {"10.0.0.1", "10.0.0.2"}
    assert store.mode == "sqlite"


def test_load_empty_returns_empty_list(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    assert store.load() == []


def test_save_replaces_previous_content(tmp_path: Path) -> None:
    """全量替换语义 —— 与原 JSON 实现一致（写进去什么，读出来就是什么）。"""
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1"), _asset("10.0.0.2")])
    store.save([_asset("10.0.0.3")])
    out = store.load()
    assert len(out) == 1
    assert out[0]["host"] == "10.0.0.3"


def test_assets_without_host_are_skipped(tmp_path: Path) -> None:
    """没有 host 的记录无法定位，丢弃而不是让整批失败。"""
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1"), {"vendor": "x"}, {"host": "  "}])
    out = store.load()
    assert len(out) == 1


def test_nested_structures_survive_roundtrip(tmp_path: Path) -> None:
    """嵌套 dict / list 必须原样保留 —— 资产结构随版本演进。"""
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    item = _asset("10.0.0.1", services=[{"port": 80, "tags": ["a", "b"]}],
                  tech_stack=["php", "nginx"], meta={"deep": {"x": [1, 2, {"y": 3}]}})
    store.save([item])
    out = store.load()[0]
    assert out["services"][0]["tags"] == ["a", "b"]
    assert out["meta"]["deep"]["x"][2]["y"] == 3


# ---------------------------------------------------------------- 迁移
def test_migrates_from_json_and_keeps_original(tmp_path: Path) -> None:
    """旧的 assets.json 要自动导入，且**原文件保留不删**。

    保留原文件是数据安全底线：迁移出错可以人工回退。
    """
    jf = tmp_path / "assets.json"
    original = [_asset("10.0.0.1"), _asset("10.0.0.2")]
    jf.write_text(json.dumps(original, ensure_ascii=False), encoding="utf-8")

    store = AssetStore(tmp_path / "a.db", jf)
    n = store._migrate_from_json()
    assert n == 2, "应导入 2 条"
    assert len(store.load()) == 2
    assert jf.exists(), "原 JSON 文件必须保留 —— 出问题可人工回退"


def test_migration_does_not_overwrite_existing_data(tmp_path: Path) -> None:
    """数据库已有数据时，迁移不能覆盖。"""
    jf = tmp_path / "assets.json"
    jf.write_text(json.dumps([_asset("10.0.0.9")]), encoding="utf-8")
    store = AssetStore(tmp_path / "a.db", jf)
    store.save([_asset("10.0.0.1")])
    assert store._migrate_from_json() == 0
    assert [a["host"] for a in store.load()] == ["10.0.0.1"]


def test_migration_skips_invalid_json(tmp_path: Path) -> None:
    """JSON 坏了不能抛异常 —— 平台仍要能启动。"""
    jf = tmp_path / "assets.json"
    jf.write_text("{ not json", encoding="utf-8")
    store = AssetStore(tmp_path / "a.db", jf)
    assert store._migrate_from_json() == 0
    assert store.load() == []


def test_migration_with_non_list_payload(tmp_path: Path) -> None:
    """JSON 内容不是数组时不该崩溃。"""
    jf = tmp_path / "assets.json"
    jf.write_text('{"a": 1}', encoding="utf-8")
    store = AssetStore(tmp_path / "a.db", jf)
    assert store._migrate_from_json() == 0


# ---------------------------------------------------------------- 回退
def test_falls_back_to_json_when_db_unusable(tmp_path: Path) -> None:
    """SQLite 不可用时自动回退 JSON —— 平台不能因存储故障整体不可用。

    做法：把 db 路径指到一个「目录」，让 sqlite3 打开必然失败。
    """
    bad_db = tmp_path / "adir"
    bad_db.mkdir()
    jf = tmp_path / "assets.json"
    jf.write_text(json.dumps([_asset("10.0.0.7")], ensure_ascii=False), encoding="utf-8")

    store = AssetStore(bad_db, jf)
    out = store.load()
    assert store.mode == "json", "应回退到 JSON"
    assert len(out) == 1 and out[0]["host"] == "10.0.0.7"
    assert store.last_error, "回退原因必须可观测"


def test_json_fallback_write_uses_atomic_write(tmp_path: Path) -> None:
    """回退写入也要原子（临时文件 + replace），不能留半截 JSON。"""
    bad_db = tmp_path / "adir"
    bad_db.mkdir()
    jf = tmp_path / "assets.json"
    store = AssetStore(bad_db, jf)
    store.save([_asset("10.0.0.1")])
    assert jf.exists()
    data = json.loads(jf.read_text(encoding="utf-8"))
    assert len(data) == 1
    # 不应留下临时文件
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert not leftovers, f"残留临时文件：{leftovers}"


# ---------------------------------------------------------------- 脱敏
def test_redaction_applied_before_write(tmp_path: Path) -> None:
    """落盘前必须脱敏 —— 攻击载荷不明文留在磁盘上。"""
    calls: list = []

    def fake_redact(obj):
        calls.append(obj)
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if isinstance(v, str) and "secret" in v:
                    out[k] = "***REDACTED***"
                else:
                    out[k] = fake_redact(v)
            return out
        if isinstance(obj, list):
            return [fake_redact(x) for x in obj]
        return obj

    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json", redact=fake_redact)
    store.save([_asset("10.0.0.1", note="my secret payload")])
    assert calls, "脱敏函数必须被调用"
    out = store.load()[0]
    assert out["note"] == "***REDACTED***"


def test_no_redaction_keeps_values(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1", note="plain")])
    assert store.load()[0]["note"] == "plain"


# ---------------------------------------------------------------- 并发
def test_concurrent_saves_do_not_corrupt(tmp_path: Path) -> None:
    """并发写不能把库写坏 —— 这是换 SQLite 的主要动机之一。"""
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            for i in range(20):
                store.save([_asset(f"10.0.{n}.{i}")])
        except Exception as exc:      # noqa: BLE001 —— 测试要收集异常
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"并发写出现异常：{errors}"
    # 库仍可读，且内容结构完整
    out = store.load()
    assert isinstance(out, list)
    for a in out:
        assert "host" in a


def test_concurrent_reads_during_write_are_safe(tmp_path: Path) -> None:
    """写的同时读，不应读到半截数据或抛异常。"""
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1")])
    errors: list[Exception] = []
    stop = threading.Event()

    def reader() -> None:
        try:
            while not stop.is_set():
                store.load()
        except Exception as exc:      # noqa: BLE001
            errors.append(exc)

    r = threading.Thread(target=reader)
    r.start()
    try:
        for i in range(30):
            store.save([_asset(f"10.0.0.{i}")])
    finally:
        stop.set()
        r.join()
    assert not errors, f"并发读写出现异常：{errors}"


# ---------------------------------------------------------------- 规模
def test_large_scale_roundtrip(tmp_path: Path) -> None:
    """一万条资产要能完整存取 —— 这是换存储的原始动因。"""
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    items = [_asset(f"10.{i // 256}.{i % 256}", services=[{"port": 80}]) for i in range(10000)]
    store.save(items)
    out = store.load()
    assert len(out) == 10000
    assert len({a["host"] for a in out}) == 10000


# ---------------------------------------------------------------- 描述
def test_describe_reports_backend(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1")])
    d = store.describe()
    assert d["backend"] == "sqlite"
    assert d["db_exists"] is True
    assert d["last_error"] is None


# ---------------------------------------------------------------- 增量写
def test_upsert_inserts_new_and_updates_existing(tmp_path: Path) -> None:
    """upsert 语义：不存在则插入，存在则覆盖，且不影响其它行。"""
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1", note="old"),
                _asset("10.0.0.2", note="untouched")])

    store.upsert(_asset("10.0.0.1", note="new"))
    store.upsert(_asset("10.0.0.3", note="fresh"))

    out = {a["host"]: a for a in store.load()}
    assert len(out) == 3
    assert out["10.0.0.1"]["note"] == "new", "同 host 应被覆盖"
    assert out["10.0.0.2"]["note"] == "untouched", "其它行不应被改动"
    assert out["10.0.0.3"]["note"] == "fresh"


def test_upsert_without_host_is_ignored(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.upsert({"vendor": "x"})
    store.upsert({"host": "  "})
    assert store.load() == []


def test_upsert_applies_redaction(tmp_path: Path) -> None:
    """增量写也要脱敏 —— 不能因为换了写入路径就漏掉。"""
    def fake_redact(obj):
        if isinstance(obj, dict):
            return {k: ("***" if k == "note" else v) for k, v in obj.items()}
        return obj

    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json", redact=fake_redact)
    store.upsert(_asset("10.0.0.1", note="payload"))
    assert store.load()[0]["note"] == "***"


def test_delete_removes_single_row(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1"), _asset("10.0.0.2")])
    assert store.delete("10.0.0.1") is True
    assert [a["host"] for a in store.load()] == ["10.0.0.2"]
    assert store.delete("10.0.0.1") is False, "重复删除应返回 False"
    assert store.delete("") is False


def test_get_returns_single_row(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    store.save([_asset("10.0.0.1", vendor="Canonical"), _asset("10.0.0.2")])
    got = store.get("10.0.0.1")
    assert got is not None and got["vendor"] == "Canonical"
    assert store.get("10.9.9.9") is None
    assert store.get("") is None


def test_count_matches_length(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "a.db", tmp_path / "assets.json")
    assert store.count() == 0
    store.save([_asset(f"10.0.0.{i}") for i in range(17)])
    assert store.count() == 17
    assert store.count() == len(store.load())


def test_incremental_cost_is_independent_of_ledger_size(tmp_path: Path) -> None:
    """增量写的代价不应随台账规模增长 —— 这是换 SQLite 的全部意义。

    如果有人把 upsert 改回「读全部 + 写全部」，这条会失败。
    """
    import time

    def timed_edit(n: int) -> float:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            store = AssetStore(td / "a.db", td / "assets.json")
            store.save([_asset(f"10.0.{i // 256}.{i % 256}") for i in range(n)])
            t0 = time.perf_counter()
            row = store.get("10.0.0.1")
            row["group"] = "x"
            store.upsert(row)
            dt = time.perf_counter() - t0
            store.close()
            return dt

    small = timed_edit(200)
    large = timed_edit(10000)
    # 允许 10 倍余量：只要不是「与规模成正比」就能过
    assert large < max(small * 10, 0.2), (
        f"增量写耗时随规模增长：200 条 {small*1000:.1f}ms，"
        f"10000 条 {large*1000:.1f}ms —— 说明退化成全量重写了")
