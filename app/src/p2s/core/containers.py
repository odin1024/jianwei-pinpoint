"""容器内 PHP 清点（M6）：宿主机上看不见容器里的 PHP，但没有它就会整片漏报。

思路与取舍：
  · 只做**非侵入式**读取：`docker ps` 拿容器清单，从**镜像标签/名称**推断 PHP 版本
    （`php:8.1-fpm`、`wordpress:6.2-php8.1` 这类命名非常常见）；
  · 不做 `docker exec` 默认探测：那会在客户容器里执行命令，属于侵入操作，
    需要显式开启（`P2S_CONTAINER_EXEC=1`）才尝试；
  · 容器版本仅作**线索**：镜像标签可能被改，因此结论标注 `source=image-tag`，
    置信度低于本地二进制取证；真正的确定性判定仍需容器内 Agent。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

#: 从镜像名/标签里提取 PHP 版本：php:8.1、php-fpm:8.1.27、wordpress:6.2-php8.1
_TAG_PHP = re.compile(r"php[:\-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_IMG_PHP = re.compile(r"^(?:library/)?php(?::|$)", re.IGNORECASE)


@dataclass
class ContainerInstall:
    container: str
    image: str
    version: Optional[str] = None
    sapi: Optional[str] = None
    source: str = "image-tag"
    note: str = ""
    #: 运行时补丁标志：True=存在（已修）、False=不存在、None=未探测
    patch_flag: Optional[bool] = None
    #: 版本是否经容器内 exec 核实（False 表示只来自镜像标签）
    verified: bool = False

    def to_dict(self) -> dict:
        return {"path": f"container:{self.container}", "container": self.container,
                "image": self.image, "version": self.version, "sapi": self.sapi,
                "source": self.source, "note": self.note,
                "patch_flag": self.patch_flag, "verified": self.verified}


def _run(args: list[str], timeout: float = 6.0) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or b"").decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def docker_available() -> bool:
    return shutil.which("docker") is not None


def parse_php_from_image(image: str) -> tuple[Optional[str], Optional[str]]:
    """从镜像名推断 (PHP 版本, SAPI)。推断不出就返回 (None, None)。"""
    img = (image or "").strip()
    if not img:
        return None, None
    sapi = None
    low = img.lower()
    if "fpm" in low:
        sapi = "fpm-fcgi"
    elif "apache" in low:
        sapi = "apache2handler"
    elif "cli" in low:
        sapi = "cli"

    m = _TAG_PHP.search(img)
    if m:
        return m.group(1), sapi
    # 纯 php 镜像但标签里没写版本（如 php:latest / php:fpm）→ 无法判定
    if _IMG_PHP.search(img) or "php" in low.split(":")[0].split("/")[-1]:
        return None, sapi
    return None, None


def list_containers() -> list[dict]:
    """返回运行中的容器 [{id, image, name}]；docker 不可用则空列表。"""
    if not docker_available():
        return []
    code, out = _run(["docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"])
    if code != 0 or not out.strip():
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        rows.append({"id": parts[0].strip(), "image": parts[1].strip(), "name": parts[2].strip()})
    return rows


def _probe_inside(name: str, timeout: float = 10.0) -> tuple[Optional[str], Optional[str], Optional[bool]]:
    """容器内核实：版本 / SAPI / 补丁标志。返回 (version, sapi, patch_flag)。"""
    rc, out = _run(["docker", "exec", name, "php", "-r",
                    'echo PHP_VERSION, "|", PHP_SAPI, "|",'
                    'var_export(ini_get("memory_hard_limit_percent"), true);'], timeout=timeout)
    if rc != 0 or "|" not in out:
        return None, None, None
    parts = out.strip().split("|")
    ver = parts[0].strip() or None
    sapi = parts[1].strip() if len(parts) > 1 else None
    flag_txt = parts[2].strip().lower() if len(parts) > 2 else ""
    flag: Optional[bool] = None
    if "false" in flag_txt:
        flag = False
    elif flag_txt.startswith("''") or "null" in flag_txt or flag_txt.startswith("string"):
        flag = True
    return ver, sapi, flag


def scan_containers(deadline: float | None = None) -> tuple[list[ContainerInstall], list[str]]:
    """清点容器里的 PHP。返回 (安装点, 说明/错误)。

    deadline 是单调时钟的上限时刻。docker exec 是逐个容器串行执行的，
    容器多的时候线性累加，必须有上界，否则取证任务会一直挂着。
    """
    if not docker_available():
        return [], ["未检测到 docker CLI，跳过容器清点（容器内 PHP 对本次检测不可见）"]
    rows = list_containers()
    if not rows:
        return [], ["docker CLI 存在但未读到运行中的容器（可能无权限或未启动容器）"]

    out: list[ContainerInstall] = []
    exec_allowed = os.environ.get("P2S_CONTAINER_EXEC") == "1"
    timeout_notes: list[str] = []
    for idx, c in enumerate(rows):
        if deadline is not None and time.monotonic() > deadline:
            timeout_notes.append(
                f"容器清点已达时间预算：共 {len(rows)} 个容器，"
                f"已检查 {idx} 个，剩余 {len(rows) - idx} 个未检查")
            break
        ver, sapi = parse_php_from_image(c["image"])
        if ver is None and not sapi:
            continue                      # 与 PHP 无关的容器直接跳过
        note = "版本来自镜像标签，未经容器内核实"
        verified = False
        patch_flag = None
        # 开启 exec 时以容器内实际值为准：版本可信 + 取补丁标志
        if exec_allowed:
            _t = 10.0
            if deadline is not None:
                _t = max(1.0, min(10.0, deadline - time.monotonic()))
            _ver, _sapi, _flag = _probe_inside(c["name"], timeout=_t)
            if _ver:
                ver = _ver
                sapi = _sapi or sapi
                patch_flag = _flag
                verified = True
                note = "版本与补丁标志经容器内 php 核实"
            else:
                note = "已开启 exec 但无法进入容器（镜像无 php 或权限不足）"
        if ver is None:
            note = "镜像标签未含版本，需开启 P2S_CONTAINER_EXEC 或容器内 Agent"
        out.append(ContainerInstall(container=c["name"], image=c["image"],
                                    version=ver, sapi=sapi, note=note,
                                    patch_flag=patch_flag, verified=verified))
    if not out:
        return [], [f"清点 {len(rows)} 个容器，未发现 PHP 运行时", *timeout_notes]
    return out, timeout_notes


# --------------------------------------------------------------------------
# Kubernetes：Pod 里的 PHP 同样对宿主机隐形，且比 Docker 更常见于生产环境
# --------------------------------------------------------------------------
def kubectl_available() -> bool:
    return shutil.which("kubectl") is not None


def list_pods() -> list[dict]:
    """返回 [{ns, pod, image}]；kubectl 不可用或无权限则空。"""
    if not kubectl_available():
        return []
    code, out = _run(["kubectl", "get", "pods", "-A", "-o", "json"], timeout=12)
    if code != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    rows: list[dict] = []
    for item in data.get("items") or []:
        meta = item.get("metadata") or {}
        ns = meta.get("namespace") or "default"
        name = meta.get("name") or "?"
        for c in ((item.get("spec") or {}).get("containers") or []):
            img = c.get("image") or ""
            if img:
                rows.append({"ns": ns, "pod": name, "image": img})
    return rows


def scan_kubernetes(deadline: float | None = None) -> tuple[list[ContainerInstall], list[str]]:
    if deadline is not None and time.monotonic() > deadline:
        return [], ["Kubernetes 清点已跳过：取证已达时间预算"]
    if not kubectl_available():
        return [], ["未检测到 kubectl，跳过 Kubernetes 清点"]
    rows = list_pods()
    if not rows:
        return [], ["kubectl 存在但未读到 Pod（可能无权限或集群不可达）"]
    out: list[ContainerInstall] = []
    for r in rows:
        ver, sapi = parse_php_from_image(r["image"])
        if ver is None and not sapi:
            continue
        out.append(ContainerInstall(
            container=f'pod/{r["ns"]}/{r["pod"]}', image=r["image"],
            version=ver, sapi=sapi,
            note="版本来自镜像标签（K8s），未经 Pod 内核实",
        ))
    if not out:
        return [], [f"清点 {len(rows)} 个 Pod 容器，未发现 PHP 运行时"]
    return out, []
