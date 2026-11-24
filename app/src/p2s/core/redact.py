"""敏感内容脱敏。

为什么需要：
  检测命中时，证据里会包含攻击者的原始载荷（例如上传文件名里的 PHP 代码）。
  如果原样写进报告，会造成两个问题：
    1. 报告文件本身会被客户的杀毒 / EDR 判定为恶意文件，无法打开或上传
    2. 载荷在报告里二次传播，扩大暴露面

策略：保留可判定的结构性特征（长度、是否存在代码标记），抹掉可执行内容。
"""
from __future__ import annotations

import re

# PHP 代码块（含开标签到结束标签）
_PHP_BLOCK = re.compile(r"<\?(?:php|=).*?\?>", re.IGNORECASE | re.DOTALL)

# 序列化对象前缀
_SERIALIZED = re.compile(r"\|(?:O|C|a|r):\d+:")

# 长 base64 / hex 串
_B64 = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")
_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")

# 命令执行类调用
_CMD = re.compile(
    r"\b(system|exec|shell_exec|passthru|popen|proc_open|eval|assert)\s*\([^)]{0,120}\)",
    re.IGNORECASE,
)


def redact(text: str, *, max_len: int = 240) -> str:
    """把文本中的可执行载荷替换为结构占位符。"""
    if not text:
        return text
    out = text
    out = _PHP_BLOCK.sub(lambda m: f"[PHP-CODE-BLOCK len={len(m.group(0))}]", out)
    out = _SERIALIZED.sub(lambda m: f"[SERIALIZED-OBJ len={len(m.group(0))}]", out)
    out = _CMD.sub(lambda m: f"[{m.group(1)}-CALL len={len(m.group(0))}]", out)
    out = _B64.sub(lambda m: f"[BASE64-BLOB len={len(m.group(0))}]", out)
    out = _HEX.sub(lambda m: f"[HEX-BLOB len={len(m.group(0))}]", out)
    if len(out) > max_len:
        out = out[:max_len] + "..."
    return out


def redact_obj(obj, *, max_len: int = 240):
    """递归脱敏任意可 JSON 序列化的结构。"""
    if isinstance(obj, str):
        return redact(obj, max_len=max_len)
    if isinstance(obj, dict):
        return {k: redact_obj(v, max_len=max_len) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, max_len=max_len) for v in obj]
    return obj