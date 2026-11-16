"""数据保留：扫描报告与上传文件的清理策略。

放在 core（不依赖 console），这样 `p2s prune` 不需要拉起整个控制台栈
——否则光是导入 ops_api 就会初始化会话、生成随机口令。

策略（两道）：
1. **重复清理**：同一输入（同一份日志/同一网段）保留最近 N 份，早于 M 天的才删；
2. **总量上限**：超过 max_total 就从最旧的开始删，避免无限增长。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


def default_data_dir() -> Path:
    return Path(os.environ.get("P2S_DATA_DIR", "./p2s-data"))


def _dedupe_key(d: dict) -> str:
    """同一输入的判定键：优先 target_label，其次 scan_id 前缀（去掉序号）。"""
    label = str(d.get("target_label") or "").strip()
    kind = str(d.get("kind") or "")
    if label:
        return f"{kind}|{label}"
    return f"{kind}|{'_'.join(str(d.get('scan_id') or '').split('-')[:-1])}"


def prune_scans(scans_dir: Path, keep: int = 3, min_age_days: int = 7,
                max_total: int = 0, apply: bool = True) -> dict:
    if not scans_dir.exists():
        return {"removed": 0, "kept_groups": 0, "capped": 0}

    groups: dict[str, list[tuple[float, Path]]] = {}
    for f in scans_dir.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        groups.setdefault(_dedupe_key(d), []).append((f.stat().st_mtime, f))

    removed = 0
    for files in groups.values():
        files.sort(reverse=True)
        for mtime, f in files[keep:]:
            if (time.time() - mtime) / 86400 < min_age_days:
                continue
            removed += 1
            if apply:
                for ext in (".json", ".md", ".html"):
                    (f.parent / (f.stem + ext)).unlink(missing_ok=True)

    capped = 0
    if max_total > 0:
        left = sorted(scans_dir.glob("*.json"),
                      key=lambda f: f.stat().st_mtime, reverse=True)
        for f in left[max_total:]:
            capped += 1
            if apply:
                for ext in (".json", ".md", ".html"):
                    (f.parent / (f.stem + ext)).unlink(missing_ok=True)

    return {"removed": removed, "kept_groups": len(groups),
            "capped": capped, "keep": keep,
            "min_age_days": min_age_days, "max_total": max_total}


def prune_uploads(upload_dir: Path, max_age_days: int = 7, apply: bool = True) -> dict:
    if not upload_dir.exists():
        return {"removed": 0, "scanned": 0}
    cutoff = time.time() - max_age_days * 86400
    removed = scanned = 0
    for f in upload_dir.iterdir():
        if not f.is_file():
            continue
        scanned += 1
        try:
            if f.stat().st_mtime < cutoff:
                removed += 1
                if apply:
                    f.unlink(missing_ok=True)
        except OSError:
            continue
    return {"removed": removed, "scanned": scanned, "max_age_days": max_age_days}
