"""php2shell 检测规则库。

规则参考并扩展了 ikow/php2shell-poc 已发布的 Suricata / Sigma / ModSecurity 规则，
以及 NCSC-NL、Cloudflare、TU Delft INTELLAB 的一手观测。

重要约束：标准访问日志**不记录请求体**。因此标注 requires="body" 的规则，
只有在 WAF 日志、mod_dumpio / nginx $request_body 落盘、或 IDS 告警流中才能命中。
扫描前会检查日志字段是否满足规则所需，缺失时在报告中显式标注"不可覆盖"。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Rule:
    """一条检测规则。

    dimension: request | response | host | behavior | recon
    requires : 命中该规则所需的日志字段
               body | req_headers | resp_body | status | uri | ua | any
    """

    id: str
    name: str
    dimension: str
    severity: str
    cves: tuple[str, ...]
    requires: str
    description: str
    reference: str = ""
    notes: str = ""
    # 供 logscan 使用的可执行判定
    matcher: Optional[str] = field(default=None, compare=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "dimension": self.dimension,
            "severity": self.severity,
            "cves": list(self.cves),
            "requires": self.requires,
            "description": self.description,
            "reference": self.reference,
            "notes": self.notes,
        }


CVES = ("CVE-2026-109618", "CVE-2026-109619")

RULES: tuple[Rule, ...] = (
    Rule(
        id="P2S-REQ-001",
        name="multipart 请求体含 PHP_SESSION_UPLOAD_PROGRESS",
        dimension="request",
        severity="critical",
        cves=CVES,
        requires="body",
        description=(
            "两个 CVE 的主攻击面。PHP 的 session.upload_progress 功能会在请求解析阶段"
            "发布会话/解码器状态，是预认证 UAF 的生产者。正常业务几乎不使用该字段。"
        ),
        reference="https://github.com/ikow/php2shell-poc/blob/main/detection/php2shell.rules",
        notes="单条命中率最高、误报近乎为零的规则。",
        matcher="upload_progress",
    ),
    Rule(
        id="P2S-REQ-002",
        name="multipart 请求体含 PHPSESSID 表单字段",
        dimension="request",
        severity="high",
        cves=CVES,
        requires="body",
        description="会话固定信号：攻击者把 PHPSESSID 放进表单字段，尝试劫持会话。",
        matcher="phpsessid_in_body",
    ),
    Rule(
        id="P2S-REQ-003",
        name="上传 filename 中含 PHP 代码",
        dimension="request",
        severity="critical",
        cves=CVES,
        requires="body",
        description=(
            "会话投毒：把 PHP 代码塞进上传文件名元数据，使其写入 session 文件，"
            "再通过本地文件包含（LFI）执行。"
        ),
        matcher="php_in_filename",
    ),
    Rule(
        id="P2S-REQ-004",
        name="上传 filename 中含序列化 PHP 对象",
        dimension="request",
        severity="critical",
        cves=("CVE-2026-109619",),
        requires="body",
        description="handler 错配攻击：filename 中携带 pipe + 序列化对象，触发错误处理器的反序列化。",
        matcher="serialized_in_filename",
    ),
    Rule(
        id="P2S-REQ-005",
        name="上传 filename 异常超长",
        dimension="request",
        severity="medium",
        cves=CVES,
        requires="body",
        description="会话膨胀 / 内存放大信号：超大 filename 消耗 PHP 内部内存远超线上体积。",
        matcher="oversized_filename",
    ),
    Rule(
        id="P2S-REQ-006",
        name="chunked 传输的 multipart POST",
        dimension="request",
        severity="high",
        cves=("CVE-2026-109618",),
        requires="req_headers",
        description=(
            "缺少 Content-Length 的 multipart 请求可绕过 PHP 的 post_max_size 初始检查，"
            "持续投递 body 直至耗尽 memory_limit。"
        ),
        matcher="chunked_multipart",
    ),
    Rule(
        id="P2S-REQ-007",
        name="URL 参数中出现 session 文件路径",
        dimension="request",
        severity="high",
        cves=CVES,
        requires="uri",
        description="LFI 触发信号：请求参数引用 sess_xxx 会话文件路径，用于执行被投毒的会话。",
        matcher="session_path_in_uri",
    ),
    Rule(
        id="P2S-RES-001",
        name="响应体出现 PHP 内存耗尽错误",
        dimension="response",
        severity="high",
        cves=("CVE-2026-109618",),
        requires="resp_body",
        description="OOM 路径已被触发的直接证据。",
        matcher="oom_in_response",
    ),
    Rule(
        id="P2S-RES-002",
        name="响应体出现会话销毁失败",
        dimension="response",
        severity="critical",
        cves=("CVE-2026-109619",),
        requires="resp_body",
        description="陈旧状态利用的直接证据：worker 试图释放已失效的会话对象。",
        matcher="session_destruction_failed",
    ),
    Rule(
        id="P2S-RES-003",
        name="PHPSESSID Cookie 长度异常",
        dimension="response",
        severity="critical",
        cves=CVES,
        requires="resp_headers",
        description="堆泄漏信号：会话 cookie 被异常填充，常见于 UAF 后的内存破坏。",
        matcher="anomalous_sessionid_length",
    ),
    Rule(
        id="P2S-REC-001",
        name="高频 upload_progress 探测",
        dimension="recon",
        severity="low",
        cves=CVES,
        requires="any",
        description="同一来源在时间窗内反复发起 upload_progress 探测，判定为自动化扫描。",
        matcher="probe_burst",
    ),
    Rule(
        id="P2S-REC-003",
        name="扫描器 User-Agent",
        dimension="recon",
        severity="medium",
        cves=CVES,
        requires="ua",
        description=(
            "已知的 php2shell 扫描器会在 User-Agent 中自报家门（php2shell-scan/*、p2srun/*）。"
            "这是无需请求体的最低成本检测点，标准访问日志即可覆盖。"
        ),
        matcher="scanner_user_agent",
    ),
    Rule(
        id="P2S-REC-002",
        name="响应头暴露易受攻击的 PHP 版本",
        dimension="recon",
        severity="info",
        cves=CVES,
        requires="resp_headers",
        description="版本横幅泄露，结合版本判定即可给出风险等级。",
        matcher="vulnerable_version_banner",
    ),
)


def rules_by_dimension(dimension: str) -> list[Rule]:
    return [r for r in RULES if r.dimension == dimension]


def get_rule(rule_id: str) -> Optional[Rule]:
    for r in RULES:
        if r.id == rule_id:
            return r
    return None


def coverage_report(record_fields: set[str]) -> dict:
    """根据日志实际拥有的字段，评估规则集的可覆盖情况。"""
    covered, uncovered = [], []
    for r in RULES:
        (covered if r.requires == "any" or r.requires in record_fields else uncovered).append(r.id)
    return {"covered": covered, "uncovered": uncovered}
