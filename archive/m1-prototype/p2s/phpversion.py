"""PHP 版本解析与受影响判定

这是整个引擎最容易写错、也最容易被客户质疑的地方（04 文档 13 章），
因此单独成模块并配完整单测。

需要处理的输入形态：
    8.4.27
    8.4.27-1ubuntu1.2
    8.4.27-1.el9
    8.4.27+deb12u1
    8.4.27-1kylin1.3
    8.4.27RC1 / 8.4.27-dev / 8.4.27beta1
    8.1.2-1kylin1
    PHP/8.3.14
    php-fpm8.2
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

VERSION_RE = re.compile(
    r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?P<pre>(?:RC|rc|beta|alpha|dev)\d*)?"
    r"(?P<suffix>(?:[-+~.][0-9A-Za-z.+~_-]*)?)"
)


class VersionStatus(str, Enum):
    PATCHED = "patched"
    VULNERABLE = "vulnerable"
    VULNERABLE_EOL = "vulnerable_eol"   # EOL 分支：装到该分支最新版仍受影响
    PRERELEASE = "prerelease"           # RC/beta/dev 不判已修复
    UNKNOWN_BRANCH = "unknown_branch"   # 未收录的分支
    UNPARSEABLE = "unparseable"


# 官方修复版本（PHP 2026-10-21 安全发布）
FIXED_VERSIONS: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

# 无官方修复的分支（可追溯至 5.4）
EOL_BRANCHES: set[tuple[int, int]] = {
    (8, 1), (8, 0),
    (7, 4), (7, 3), (7, 2), (7, 1), (7, 0),
    (5, 6), (5, 5), (5, 4), (5, 3),
}

# 安全支持到期日（用于「到期提醒」，不是漏洞判定依据）
SUPPORT_UNTIL: dict[tuple[int, int], str] = {
    (8, 5): "2029-12-31",
    (8, 4): "2028-12-31",
    (8, 3): "2027-12-31",
    (8, 2): "2026-12-31",   # 关键：最近的一个时间节点
}


@dataclass(frozen=True, slots=True)
class PhpVersion:
    major: int
    minor: int
    patch: int
    pre: str | None
    suffix: str
    raw: str

    @property
    def branch(self) -> tuple[int, int]:
        return (self.major, self.minor)

    @property
    def branch_str(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def tuple3(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def is_prerelease(self) -> bool:
        return bool(self.pre)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


def parse_version(text: str | None) -> PhpVersion | None:
    """从任意字符串中提取 PHP 版本。取第一个匹配。"""
    if not text:
        return None
    m = VERSION_RE.search(str(text))
    if not m:
        return None
    return PhpVersion(
        major=int(m.group("major")),
        minor=int(m.group("minor")),
        patch=int(m.group("patch")),
        pre=m.group("pre") or None,
        suffix=(m.group("suffix") or "").strip("-+~") or "",
        raw=str(text).strip(),
    )


def evaluate(version: PhpVersion | str | None) -> tuple[VersionStatus, str]:
    """判定版本状态，返回 (状态, 人类可读说明)。

    关键规则（04 文档 13.2）：
      1. 预发布版本不得判为已修复
      2. EOL 分支无论 patch 号多大都判受影响
      3. 区间比较用三元组，不用字符串
    """
    if version is None:
        return VersionStatus.UNPARSEABLE, "无法解析版本号"
    if isinstance(version, str):
        parsed = parse_version(version)
        if parsed is None:
            return VersionStatus.UNPARSEABLE, f"无法解析版本号：{version}"
        version = parsed

    if version.is_prerelease:
        return (
            VersionStatus.PRERELEASE,
            f"{version} 为预发布版本（{version.pre}），不能视为已修复",
        )

    if version.branch in EOL_BRANCHES:
        note = (
            f"{version.branch_str} 分支已停止支持（可追溯至 PHP 5.4），"
            f"官方无修复版本，装到该分支最新版 {version} 仍受影响"
        )
        return VersionStatus.VULNERABLE_EOL, note

    fixed = FIXED_VERSIONS.get(version.branch)
    if fixed is None:
        return (
            VersionStatus.UNKNOWN_BRANCH,
            f"{version.branch_str} 分支未收录在规则库中，无法判定（需更新规则包）",
        )

    fixed_str = f"{fixed[0]}.{fixed[1]}.{fixed[2]}"
    if version.tuple3 >= fixed:
        return VersionStatus.PATCHED, f"{version} ≥ 修复版本 {fixed_str}"
    return (
        VersionStatus.VULNERABLE,
        f"{version} < 修复版本 {fixed_str}（{version.branch_str} 分支受影响）",
    )


def is_affected(version: PhpVersion | str | None) -> bool | None:
    """True 受影响 / False 已修复 / None 无法判定。"""
    status, _ = evaluate(version)
    if status in (VersionStatus.VULNERABLE, VersionStatus.VULNERABLE_EOL):
        return True
    if status == VersionStatus.PATCHED:
        return False
    return None


def fixed_for(version: PhpVersion) -> str | None:
    fixed = FIXED_VERSIONS.get(version.branch)
    if not fixed:
        return None
    return f"{fixed[0]}.{fixed[1]}.{fixed[2]}"


def support_end(version: PhpVersion) -> str | None:
    return SUPPORT_UNTIL.get(version.branch)


def upgrade_path(version: PhpVersion) -> str:
    """给出升级建议：受影响分支给目标版本，EOL 分支给迁移建议。"""
    status, _ = evaluate(version)
    if status == VersionStatus.VULNERABLE_EOL:
        return "无官方修复，必须迁移至 8.4.x 或 8.5.x"
    fixed = fixed_for(version)
    if fixed:
        return f"升级至 {fixed} 或更高"
    return "需查询官方公告确认修复版本"
