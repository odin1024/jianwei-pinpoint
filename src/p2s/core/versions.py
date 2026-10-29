"""PHP 版本 -> php2shell 修复状态判定。

数据来源：PHP 官方 2026-10-21 安全公告
https://www.php.net/archive/2026.php#2026-10-21-5
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Optional

#: 各维护分支的已修复版本
FIXED_RELEASES: dict[str, str] = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12",
}

#: 开发中分支（含修复但为 RC，不建议上生产）
DEV_BRANCHES: frozenset[str] = frozenset({"8.6"})

#: 官方已停止安全维护的最高分支（需依赖发行版 / LTS 回补）
LAST_SUPPORTED_BRANCH = "8.2"

#: 官方已 EOL 的分支，PHP 团队仅提供 7.4 / 8.0 / 8.1 最小源码回补
EOL_BACKPORT_BRANCHES: frozenset[str] = frozenset({"7.4", "8.0", "8.1"})

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:[-.]?([A-Za-z0-9.\-]+))?")


class Status:
    """判定结果状态。"""

    PATCHED = "patched"
    VULNERABLE = "vulnerable"
    EOL_UNPATCHABLE = "eol_unpatchable"
    EOL_BACKPORT_AVAILABLE = "eol_backport_available"
    DEV = "dev_branch"
    UNKNOWN = "unknown"


@dataclass
class Verdict:
    """单个版本的判定结论。"""

    version: str
    status: str
    branch: Optional[str]
    fixed_release: Optional[str]
    confidence: float
    reason: str

    @property
    def needs_action(self) -> bool:
        return self.status in (Status.VULNERABLE, Status.EOL_UNPATCHABLE, Status.EOL_BACKPORT_AVAILABLE)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["needs_action"] = self.needs_action
        return d


def parse_version(raw: str | None) -> Optional[tuple[int, int, int, Optional[str]]]:
    """从任意字符串中提取 PHP 版本号。

    支持 '8.5.12'、'PHP/8.4.27'、'8.3.36-1'、'8.2.35RC1' 等形态。
    """
    if not raw:
        return None
    m = _VERSION_RE.search(str(raw))
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    suffix = m.group(4)
    # RC / alpha / beta 之类预发布标识
    if suffix and re.match(r"^(RC|alpha|beta|dev)", suffix, re.IGNORECASE):
        suffix = "RC" if suffix.upper().startswith("RC") else suffix.lower()
    return major, minor, patch, suffix


def _cmp(version: tuple[int, int, int, Optional[str]], target: str) -> int:
    tv = parse_version(target)
    assert tv is not None
    a = (version[0], version[1], version[2])
    b = (tv[0], tv[1], tv[2])
    return (a > b) - (a < b)


def classify(raw_version: str | None, *, prerelease_is_dev: bool = True) -> Verdict:
    """判定一个 PHP 版本相对 php2shell 修复基线的状态。"""
    parsed = parse_version(raw_version)
    if parsed is None:
        return Verdict(
            version=str(raw_version or ""),
            status=Status.UNKNOWN,
            branch=None,
            fixed_release=None,
            confidence=0.0,
            reason="未能解析出版本号",
        )

    major, minor, patch, suffix = parsed
    branch = f"{major}.{minor}"

    # 预发布 / RC 版本
    if suffix and prerelease_is_dev:
        return Verdict(
            version=f"{major}.{minor}.{patch}",
            status=Status.DEV,
            branch=branch,
            fixed_release=None,
            confidence=0.9,
            reason=f"检测到预发布版本标识 '{suffix}'，不可用于生产",
        )

    # 8.1 及更早
    if branch in EOL_BACKPORT_BRANCHES or (major, minor) < (8, 2):
        if branch in EOL_BACKPORT_BRANCHES:
            reason = (
                f"PHP {branch} 已停止官方安全维护；PHP 团队提供最小源码回补，"
                "但更推荐使用发行版/LTS 厂商的补丁或升级到 8.3+"
            )
            status = Status.EOL_BACKPORT_AVAILABLE
        else:
            reason = f"PHP {branch} 已 EOL，官方无补丁可用，必须依赖发行版回补或立即升级"
            status = Status.EOL_UNPATCHABLE
        return Verdict(
            version=f"{major}.{minor}.{patch}",
            status=status,
            branch=branch,
            fixed_release=None,
            confidence=0.95,
            reason=reason,
        )

    # 开发中分支
    if branch in DEV_BRANCHES:
        return Verdict(
            version=f"{major}.{minor}.{patch}",
            status=Status.DEV,
            branch=branch,
            fixed_release=None,
            confidence=0.8,
            reason=f"PHP {branch} 为开发中分支，不建议用于生产",
        )

    # 受支持分支
    fixed = FIXED_RELEASES.get(branch)
    if fixed is None:
        return Verdict(
            version=f"{major}.{minor}.{patch}",
            status=Status.UNKNOWN,
            branch=branch,
            fixed_release=None,
            confidence=0.4,
            reason=f"未收录的分支 {branch}，需人工确认",
        )

    cmp_result = _cmp(parsed, fixed)
    if cmp_result >= 0:
        return Verdict(
            version=f"{major}.{minor}.{patch}",
            status=Status.PATCHED,
            branch=branch,
            fixed_release=fixed,
            confidence=0.95,
            reason=f"已修复基线 {fixed} 及以上",
        )
    return Verdict(
        version=f"{major}.{minor}.{patch}",
        status=Status.VULNERABLE,
        branch=branch,
        fixed_release=fixed,
        confidence=0.95,
        reason=f"低于修复基线 {fixed}，受影响",
    )
