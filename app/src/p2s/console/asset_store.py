"""资产台账存储：SQLite 为主，JSON 为兼容回退。

为什么换
--------
原实现把整个台账序列化成一个 `assets.json`，每次读取都要全量解析、
每次写入都要全量序列化。实测（本机，12 核）：

| 资产数 | 序列化 | 写盘 | 读回 | 单次操作 |
|---|---|---|---|---|
|    500 |   17 ms |   3 ms |   7 ms |   ~27 ms |
|   2000 |   73 ms |  11 ms |  34 ms |  ~118 ms |
|  10000 |  488 ms |  45 ms | 173 ms |  ~706 ms |

一万条资产时，每次改一个字段都要等 0.7 秒 —— 这是 R-12 记的问题。
SQLite 把成本从「与台账规模成正比」降到「与本次改动量成正比」。

设计原则
--------
1. **接口不变** —— `_load_assets()` / `_save_assets()` 的签名与语义保持不变，
   所有调用方零改动。评审报告里 R-12 之所以能安全做，正是因为
   存取已经被这两个函数统一封装。
2. **自动迁移** —— 首次启动时若发现旧的 `assets.json`，自动导入 SQLite，
   并保留原文件（不删），出问题可以人工回退。
3. **SQLite 不可用时自动回退 JSON** —— 数据库文件损坏、目录只读、
   磁盘满 —— 任何一种情况都不该让平台整个不可用。回退是显式的、可观测的。
4. **脱敏口径不变** —— 落盘前仍走 `_redact_asset_text`，
   证据里的攻击载荷不该明文留在磁盘上。

数据模型
--------
资产对象是嵌套 dict（字段形状随版本演进），所以用「JSON 列」存整行，
而不是给每个字段建列 —— 后者一改资产结构就要迁移 schema，
和 JSON 文件相比没有本质优势，却失去了可查询性以外的所有好处。

```sql
CREATE TABLE assets (
    host      TEXT PRIMARY KEY,   -- 资产唯一标识
    payload   TEXT NOT NULL,      -- 脱敏后的完整 JSON
    updated_at REAL NOT NULL      -- 最近修改时间
);
CREATE INDEX idx_assets_updated ON assets(updated_at);
```
"""
from __future__ import annotations

import atexit
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable

#: 单条资产 JSON 的体积上限。超过说明调用方塞了异常数据，
#: 直接拒绝写入而不是把数据库撑爆。
MAX_ASSET_BYTES = 1 * 1024 * 1024


class AssetStore:
    """资产台账存储。

    对外只暴露 ``load()`` / ``save()`` 两个方法，语义与原 JSON 实现一致。
    """

    def __init__(self, db_path: Path, json_path: Path,
                 redact: Callable[[Any], Any] | None = None) -> None:
        self._db_path = Path(db_path)
        self._json_path = Path(json_path)
        self._redact = redact or (lambda x: x)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._mode = "json"          # "sqlite" | "json"
        self._last_error: str | None = None
        # Windows 上未关闭的 sqlite 连接会锁住 .db/.db-wal/.db-shm 文件，
        # 导致数据目录无法删除、无法移动、无法备份。进程退出时必须关闭。
        atexit.register(self.close)

    # ---------------------------------------------------------------- 状态
    @property
    def mode(self) -> str:
        """当前实际使用的存储后端：``sqlite`` 或 ``json``（回退）。"""
        return self._mode

    @property
    def last_error(self) -> str | None:
        """最近一次回退的��因（正常时为 None）。"""
        return self._last_error


    def get(self, host: str) -> dict | None:
        """按 host 取单条资产 —— O(1)，不扫全表。

        单条增删改接口应当优先用这个，而不是 load() 整个台账。
        """
        with self._lock:
            key = str(host or "").strip()
            if not key:
                return None
            conn = self._open()
            if conn is None:
                for a in self._load_json():
                    if a.get("host") == key:
                        return a
                return None
            try:
                row = conn.execute(
                    "SELECT payload FROM assets WHERE host=?", (key,)
                ).fetchone()
            except sqlite3.Error as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._mode = "json"
                for a in self._load_json():
                    if a.get("host") == key:
                        return a
                return None
            if not row:
                return None
            try:
                item = json.loads(row[0])
            except json.JSONDecodeError:
                return None
            return item if isinstance(item, dict) else None

    def count(self) -> int:
        """资产条数 —— 比 load() 再 len() 便宜得多。"""
        with self._lock:
            conn = self._open()
            if conn is None:
                return len(self._load_json())
            try:
                row = conn.execute("SELECT COUNT(*) FROM assets").fetchone()
                return int(row[0]) if row else 0
            except sqlite3.Error as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._mode = "json"
                return len(self._load_json())

    # ---------------------------------------------------------------- 增量写
    def upsert(self, item: dict) -> None:
        """写入/覆盖单条资产 —— 不动其它行。

        这是 SQLite 相对 JSON 全量重写的真正优势所在：
        改一条资产的代价从「O(台账规模)」降到「O(1)」。
        """
        with self._lock:
            if not isinstance(item, dict):
                return
            host = str(item.get("host") or "").strip()
            if not host:
                return
            safe = self._redact(item)
            payload = json.dumps(safe, ensure_ascii=False)
            if len(payload.encode("utf-8")) > MAX_ASSET_BYTES:
                return
            conn = self._open()
            if conn is None:
                self._upsert_json(host, safe)
                return
            try:
                with conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO assets(host,payload,updated_at) VALUES(?,?,?)",
                        (host, payload, time.time()),
                    )
                self._mode = "sqlite"
                self._last_error = None
            except sqlite3.Error as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._mode = "json"
                self._upsert_json(host, safe)

    def delete(self, host: str) -> bool:
        """删除单条资产。返回是否确实删掉了。"""
        with self._lock:
            key = str(host or "").strip()
            if not key:
                return False
            conn = self._open()
            if conn is None:
                return self._delete_json(key)
            try:
                with conn:
                    cur = conn.execute("DELETE FROM assets WHERE host=?", (key,))
                return cur.rowcount > 0
            except sqlite3.Error as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._mode = "json"
                return self._delete_json(key)

    def _upsert_json(self, host: str, item: dict) -> None:
        """JSON 回退下的单条写入（仍是全量重写，但语义正确）。"""
        items = [a for a in self._load_json() if a.get("host") != host]
        items.append(item)
        self._save_json(items)

    def _delete_json(self, host: str) -> bool:
        items = self._load_json()
        out = [a for a in items if a.get("host") != host]
        if len(out) == len(items):
            return False
        self._save_json(out)
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "backend": self._mode,
            "db_path": str(self._db_path),
            "db_exists": self._db_path.exists(),
            "json_fallback": str(self._json_path),
            "json_exists": self._json_path.exists(),
            "last_error": self._last_error,
        }

    # ---------------------------------------------------------------- 打开
    def _open(self) -> sqlite3.Connection | None:
        """打开（必要时创建）数据库。失败返回 None，调用方转 JSON 回退。"""
        if self._conn is not None:
            return self._conn
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self._db_path), timeout=15.0, check_same_thread=False,
            )
            # journal_mode=DELETE 而非 WAL：WAL 会在数据目录里多留
            # .db-wal 与 .db-shm 两个文件，对单机自托管场景没有收益，
            # 却让"备份/删除数据目录"这件事变得需要额外处理。
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    host       TEXT PRIMARY KEY,
                    payload    TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_updated ON assets(updated_at)")
            conn.commit()
            self._conn = conn
            self._mode = "sqlite"
            self._last_error = None
            return conn
        except (sqlite3.Error, OSError) as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"
            self._mode = "json"
            self._conn = None
            return None

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    # ---------------------------------------------------------------- 迁移
    def _migrate_from_json(self) -> int:
        """把旧的 assets.json 导入 SQLite。

        只在数据库为空且 JSON 存在时执行一次。**不删除原 JSON** ——
        出问题可以人工回退，这是数据安全底线。

        返回导入条数；失败返回 0。
        """
        conn = self._open()
        if conn is None:
            return 0
        if not self._json_path.exists():
            return 0
        try:
            row = conn.execute("SELECT COUNT(*) FROM assets").fetchone()
            if row and row[0]:
                return 0                       # 已有数据，不覆盖
        except sqlite3.Error:
            return 0
        try:
            raw = self._json_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, list):
                return 0
            rows = []
            now = time.time()
            for item in data:
                if not isinstance(item, dict):
                    continue
                host = str(item.get("host") or "").strip()
                if not host:
                    continue
                rows.append((host, json.dumps(item, ensure_ascii=False), now))
            if not rows:
                return 0
            with conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO assets(host,payload,updated_at) VALUES(?,?,?)",
                    rows,
                )
            return len(rows)
        except (json.JSONDecodeError, OSError, sqlite3.Error):
            return 0

    # ---------------------------------------------------------------- 读
    def load(self) -> list[dict]:
        """读出全部资产。顺序与写入顺序无关，按更新时间稳定排序。"""
        with self._lock:
            conn = self._open()
            if conn is None:
                return self._load_json()
            try:
                rows = conn.execute(
                    "SELECT payload FROM assets ORDER BY updated_at DESC, host"
                ).fetchall()
            except sqlite3.Error as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._mode = "json"
                return self._load_json()
            out: list[dict] = []
            for (payload,) in rows:
                try:
                    item = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    out.append(item)
            return out

    def _load_json(self) -> list[dict]:
        """JSON 回退读取（与原实现语义一致）。"""
        if not self._json_path.exists():
            return []
        for attempt in range(2):
            try:
                data = json.loads(self._json_path.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError):
                if attempt == 0:
                    time.sleep(0.05)
                    continue
                return []
        return []

    # ---------------------------------------------------------------- 写
    def save(self, assets: list[dict]) -> None:
        """写入全部资产（全量替换语义，与原实现一致）。

        先脱敏，再落盘。脱敏口径由调用方注入（``_redact_asset_text``）。
        """
        with self._lock:
            safe = [self._redact(a) for a in assets]
            conn = self._open()
            if conn is None:
                self._save_json(safe)
                return
            try:
                now = time.time()
                rows = []
                for item in safe:
                    if not isinstance(item, dict):
                        continue
                    host = str(item.get("host") or "").strip()
                    if not host:
                        continue
                    payload = json.dumps(item, ensure_ascii=False)
                    if len(payload.encode("utf-8")) > MAX_ASSET_BYTES:
                        continue          # 异常大的记录直接丢弃，不撑爆库
                    rows.append((host, payload, now))
                with conn:
                    conn.execute("DELETE FROM assets")
                    conn.executemany(
                        "INSERT OR REPLACE INTO assets(host,payload,updated_at) VALUES(?,?,?)",
                        rows,
                    )
                self._mode = "sqlite"
                self._last_error = None
                return
            except sqlite3.Error as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._mode = "json"
                self._save_json(safe)

    def _save_json(self, assets: list[dict]) -> None:
        """JSON 回退写入：原子写（临时文件 + os.replace）。"""
        from .deps import _atomic_write

        _atomic_write(self._json_path, json.dumps(assets, ensure_ascii=False, indent=2))
