"""Kubernetes 加固：生成可直接 apply 的清单。

设计原则（与 PHP 加固一致）：
1. **只生成清单，不替用户执行**——平台永不连集群改东西；
2. **每条加固都对应一条规则**，规则库里能查到为什么；
3. **可验证**：清单能用 `kubectl apply --dry-run=server` 校验，也能实际 apply 后查回来。

产物三类：
    namespace.yaml    给命名空间打 Pod Security 标签（restricted）
    networkpolicy.yaml 默认拒绝入站/出站（放行 DNS）
    workload-patch.yaml 给现有工作负载的 securityContext 补丁片段
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Artifact:
    name: str
    content: str
    note: str


def _yaml_list(items: list[str], indent: int = 2) -> str:
    pad = " " * indent
    return "\n".join(f"{pad}- {x}" for x in items)


def build_namespace(name: str) -> Artifact:
    """命名空间打 Pod Security 标签：restricted 是 K8s 内置的最严格档位。"""
    content = f"""# 由见微 Pinpoint 生成 · 命名空间 {name} 的 Pod Security 策略
# restricted 档位会强制：非 root 运行、禁止提权、丢弃全部 capability、
# 要求 seccomp/AppArmor 配置，违反的工作负载会被 API Server 拒绝创建。
apiVersion: v1
kind: Namespace
metadata:
  name: {name}
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
"""
    return Artifact("namespace.yaml", content,
                    "给命名空间启用 Pod Security restricted 档位")


def build_network_policy(name: str) -> Artifact:
    """默认拒绝全部入站与出站，只放行 DNS 与显式声明。"""
    content = f"""# 默认拒绝：K8s 的 NetworkPolicy 是"白名单"语义，
# 一旦某个 Pod 被任何策略选中，未被放行的流量都会被丢弃。
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: {name}
spec:
  podSelector: {{}}
  policyTypes:
    - Ingress
    - Egress
  egress:
    # 只放行 DNS，否则集群内解析全部失效
    - to:
        - namespaceSelector: {{}}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
"""
    return Artifact("networkpolicy.yaml", content,
                    "默认拒绝入站/出站，仅放行 DNS")


def build_workload_patch(name: str) -> Artifact:
    """给工作负载的 securityContext 补丁（可直接 kubectl patch 或合并进 Deployment）。"""
    content = f"""# 工作负载安全上下文补丁（Deployment/StatefulSet 通用）
# 用法：kubectl -n {name} patch deployment <名称> --patch-file workload-patch.yaml
spec:
  template:
    spec:
      automountServiceAccountToken: false      # 不自动挂载 SA token，减少被盗用面
      securityContext:
        runAsNonRoot: true                     # 强制非 root
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault                 # 启用默认 seccomp，收敛 syscall
      containers:
        - name: app                            # 改成实际容器名
          securityContext:
            allowPrivilegeEscalation: false    # 禁止通过 setuid 提权
            readOnlyRootFilesystem: true       # 根文件系统只读，防落盘后门
            privileged: false
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              memory: 512Mi                    # 内存上限，OOM 只影响本 Pod
              cpu: 500m
            requests:
              memory: 256Mi
              cpu: 100m
"""
    return Artifact("workload-patch.yaml", content,
                    "工作负载的 securityContext / 资源限制补丁")


def build_all(namespace: str) -> list[Artifact]:
    return [build_namespace(namespace), build_network_policy(namespace),
            build_workload_patch(namespace)]


def checklist() -> list[dict]:
    """给前端/报告用的加固项清单（与产物对应）。"""
    return [
        {"key": "pod-security.kubernetes.io/enforce", "value": "restricted",
         "why": "命名空间级强制最严格 Pod Security 档位，违规负载无法创建",
         "artifact": "namespace.yaml"},
        {"key": "NetworkPolicy/default-deny", "value": "Ingress+Egress",
         "why": "默认拒绝横向移动，只放行 DNS 与显式白名单",
         "artifact": "networkpolicy.yaml"},
        {"key": "securityContext.runAsNonRoot", "value": "true",
         "why": "容器以非 root 运行，拿到代码执行也无法直接改系统",
         "artifact": "workload-patch.yaml"},
        {"key": "securityContext.allowPrivilegeEscalation", "value": "false",
         "why": "禁止 setuid 提权",
         "artifact": "workload-patch.yaml"},
        {"key": "securityContext.readOnlyRootFilesystem", "value": "true",
         "why": "根文件系统只读，webshell 无法落盘",
         "artifact": "workload-patch.yaml"},
        {"key": "securityContext.capabilities.drop", "value": "ALL",
         "why": "丢弃全部 Linux capability",
         "artifact": "workload-patch.yaml"},
        {"key": "seccompProfile.type", "value": "RuntimeDefault",
         "why": "收敛可用系统调用，抬高内核漏洞利用门槛",
         "artifact": "workload-patch.yaml"},
        {"key": "automountServiceAccountToken", "value": "false",
         "why": "不自动挂载 SA token，避免被用于访问 API Server",
         "artifact": "workload-patch.yaml"},
        {"key": "resources.limits.memory", "value": "512Mi",
         "why": "内存上限，OOM 型攻击只影响本 Pod，不拖垮节点",
         "artifact": "workload-patch.yaml"},
    ]
