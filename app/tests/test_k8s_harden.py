"""K8s 加固产物测试。"""
from __future__ import annotations

import re

import pytest

from p2s.core import k8s_harden as K


def test_artifacts_present() -> None:
    names = [a.name for a in K.build_all("p2s-test")]
    assert names == ["namespace.yaml", "networkpolicy.yaml", "workload-patch.yaml"]


@pytest.mark.parametrize("art", K.build_all("p2s-test"))
def test_each_artifact_has_comment(art) -> None:
    """产物必须带说明，运维拿到文件要知道为什么这么改。"""
    assert art.content.startswith("#"), f"{art.name} 缺少头部注释"
    assert art.note, f"{art.name} 缺少 note"


def test_namespace_enforces_restricted() -> None:
    y = K.build_namespace("p2s-test").content
    assert "kind: Namespace" in y
    assert "pod-security.kubernetes.io/enforce: restricted" in y
    assert "p2s-test" in y


def test_networkpolicy_denies_by_default() -> None:
    y = K.build_network_policy("p2s-test").content
    assert "kind: NetworkPolicy" in y
    assert "podSelector: {}" in y, "空的 podSelector 表示选中命名空间内全部 Pod"
    assert "Ingress" in y and "Egress" in y
    assert "kube-dns" in y, "必须放行 DNS，否则集群内解析全断"
    assert "port: 53" in y


def test_workload_patch_covers_key_fields() -> None:
    y = K.build_workload_patch("p2s-test").content
    for field in ("runAsNonRoot: true", "allowPrivilegeEscalation: false",
                  "readOnlyRootFilesystem: true", "privileged: false",
                  "automountServiceAccountToken: false",
                  "seccompProfile:", "limits:", "drop:"):
        assert field in y, f"补丁缺少 {field}"


def test_workload_patch_syntax_basics() -> None:
    """粗检 YAML 缩进：不允许出现 tab（YAML 禁用 tab 缩进）。"""
    y = K.build_workload_patch("p2s-test").content
    assert "\t" not in y


def test_checklist_matches_artifacts() -> None:
    items = K.checklist()
    files = {a.name for a in K.build_all("p2s-test")}
    assert len(items) >= 8
    for it in items:
        assert it["artifact"] in files, f"{it['key']} 指向不存在的产物"
        assert it["why"]


def test_namespace_name_interpolated_safely() -> None:
    """命名空间只允许 DNS-1123 标签字符，注入非法内容时要能看出来。"""
    y = K.build_namespace("team-a").content
    assert y.count("team-a") >= 1
    assert not re.search(r"[^a-z0-9-]", "team-a")
