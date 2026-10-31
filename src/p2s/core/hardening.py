"""配置加固：加固包生成（L1）、漂移检测（L1.5）、受控执行协议（L2）。

设计前提（必须守住）
--------------------
1. **平台永远不直接写业务主机。** 所有变更以"包"的形式产出，由运维执行或 Agent 主动拉取；
2. **执行的是声明式动作，不是任意 shell。** 动作白名单只有三项，写死在脚本里；
3. **预检不过就拒绝执行**，宁可让运维手工处理，也不冒险；
4. **一定可回滚**：改前备份、记录 sha256、验证失败自动回滚；
5. **留痕**：回执（receipt）回到平台校验后才算"已加固"。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

#: 加固动作白名单：平台只会生成这三种，Agent/脚本也只会执行这三种
ACTION_WHITELIST = ("php.ini.set", "file.backup", "service.reload")

#: 建议值来源：官方公告的缓解配置 + 社区实践（见 docs/03-情报/同类工具调研与借鉴.md）
RECOMMENDED: tuple[tuple[str, str, str, str], ...] = (
    (
        "session.upload_progress.enabled", "0", "critical",
        "php2shell 两条 CVE 共用的主触发点。rfc1867 上传进度处理器在 SAPI 启动阶段执行，"
        "早于应用代码，因此**即使站点不调用 session_start() 也可能被利用**（Chain E）。",
    ),
    (
        "session.use_only_cookies", "1", "high",
        "拒绝通过 URL/表单参数接受会话 ID，封堵把 PHPSESSID 当表单字段提交的会话固定手法。",
    ),
    (
        "session.use_strict_mode", "1", "medium",
        "拒绝客户端自选未初始化的会话 ID，降低会话固定与链式利用成功率。",
    ),
    (
        "display_errors", "0", "low",
        "生产环境不回显内部错误，避免 OOM/崩溃细节被用来判断利用是否成功。",
    ),
)


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def current_settings(host_report: dict) -> dict[str, str]:
    """从 Agent 上报里取出"实际生效值"。"""
    out: dict[str, str] = {}
    for s in host_report.get("settings") or []:
        name = s.get("name")
        if name:
            out[name] = str(s.get("actual") or "")
    return out


def _bool_norm(v: str) -> str:
    """把 On/Off/1/0/true/false 归一，避免"值不同但语义相同"被误判为待加固。"""
    s = str(v).strip().lower()
    if s in ("1", "on", "true", "yes"):
        return "1"
    if s in ("0", "off", "false", "no", ""):
        return "0"
    return s


def plan_actions(host_report: dict, target: str = "") -> list[dict]:
    """对照建议值算出需要执行的动作（L1 的输入）。"""
    cur = current_settings(host_report)
    actions: list[dict] = []
    for key, want, level, why in RECOMMENDED:
        have = cur.get(key)
        if have is None:
            continue                      # 该 PHP 不支持这个配置项，跳过
        if _bool_norm(have) == _bool_norm(want):
            continue
        actions.append({
            "action": "php.ini.set",
            "target": target or str(host_report.get("ini_path") or ""),
            "key": key,
            "from": have,
            "value": want,
            "level": level,
            "why": why,
        })
    return actions


def drift(host_report: dict, baseline: Optional[dict]) -> list[dict]:
    """漂移检测：与"上次确认过的基线"比较，发现被配置管理覆盖回去的项。"""
    if not baseline:
        return []
    cur = current_settings(host_report)
    out: list[dict] = []
    for key, want in baseline.items():
        have = cur.get(key)
        if have is None:
            continue
        if _bool_norm(have) != _bool_norm(str(want)):
            out.append({"key": key, "expected": want, "actual": have,
                        "note": "与已加固基线不一致，可能被配置管理/升级覆盖"})
    return out


def _q(v: str) -> str:
    """POSIX shell 单引号转义。"""
    return "'" + str(v).replace("'", "'\\''") + "'"


def build_pack(host: str, host_report: dict, target: str, actions: list[dict],
               token: str = "", auto_reload: bool = False) -> dict[str, str]:
    """生成加固包：harden.sh / rollback.sh / diff.patch / manifest.json / README.txt。"""
    before_sha = str(host_report.get("ini_sha256") or "")
    php_bin = str(host_report.get("php_bin") or "php")
    ts = _now()
    _is_cli = '1' if '/cli/' in str(target) else '0'
    keys = ' '.join(str(a['key']) for a in actions)

    # 每项动作一条显式调用：避免 shell 动态变量与 f-string 混用
    apply_lines = "\n".join(f"apply_kv {_q(a['key'])} {_q(a['value'])}" for a in actions)
    verify_lines = "\n".join(f"verify_kv {_q(a['key'])} {_q(a['value'])}" for a in actions)
    emit_lines = "\n".join(f"  emit {_q(a['key'])} {_q(a['value'])}" for a in actions)

    reload_block = ""
    if auto_reload:
        reload_block = (
            'say "  正在 reload PHP 服务"\n'
            'for s in php-fpm php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm apache2 httpd; do\n'
            '  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$s" 2>/dev/null; then\n'
            '    systemctl reload "$s" && say "  reloaded: $s"\n'
            "  fi\n"
            "done\n"
        )

    harden = f"""#!/bin/sh
# php2shell 配置加固包 —— 由见微 Pinpoint 生成
# 主机: {host}
# 目标: {target}
# 生成: {ts}
# 动作白名单: php.ini.set / file.backup / service.reload（脚本内不含其他能力）
set -eu
TARGET={_q(target)}
TARGET_IS_CLI={_is_cli}
PHP_BIN={_q(php_bin)}
EXPECT_SHA={_q(before_sha)}
TOKEN={_q(token)}
KEYS={_q(keys)}

say() {{ printf '%s\\n' "$*"; }}
die() {{ printf '[FAIL] %s\\n' "$*" >&2; exit "$1"; }}

say "[1/5] 预检"
[ -f "$TARGET" ] || die 10 "目标文件不存在：$TARGET"
[ -w "$TARGET" ] || die 11 "没有写权限（请用 root / 管理员执行）"
if [ -f /.dockerenv ]; then die 12 "检测到容器环境：请改用 compose 挂载 php.ini"; fi

# ---- 拒绝清单（借鉴安天：不猜、不隐式提权、不覆盖可疑文件）----
if [ -L "$TARGET" ]; then die 15 "目标是符号链接：请直接指定真实文件路径"; fi
[ "$(stat -c %h "$TARGET" 2>/dev/null || echo 1)" = "1" ] \
  || die 16 "目标有多个硬链接：请确认后去除多余链接再执行"
PERM=$(stat -c %a "$TARGET" 2>/dev/null || echo 644)
case "$PERM" in
  *[2367][0-9]|*[0-9][2367]) die 17 "目标对组或其他用户可写（权限 $PERM）：请先 chmod go-w";;
esac
for _k in $KEYS; do
  _n=$(grep -cE "^[[:space:]]*;?[[:space:]]*$_k[[:space:]]*=" "$TARGET" 2>/dev/null || true)
  [ "${{_n:-0}}" -le 1 ] || die 18 "指令 $_k 在文件中出现 $_n 次：不猜哪条生效，请先人工去重"
done
if grep -qE '^[[:space:]]*(session\\.|display_errors|memory_limit|allow_url_include)[^=]*=.*\\\\$' "$TARGET" 2>/dev/null; then
  die 19 "目标存在续行（行尾反斜杠）：请先人工整理成单行"
fi
if [ -n "$EXPECT_SHA" ]; then
  NOW_SHA=$(sha256sum "$TARGET" 2>/dev/null | cut -d' ' -f1)
  if [ "$NOW_SHA" != "$EXPECT_SHA" ]; then
    die 13 "文件与平台记录不一致：$NOW_SHA != $EXPECT_SHA"
  fi
fi
if head -5 "$TARGET" 2>/dev/null | grep -Eqi 'ansible|puppet|salt|chef|managed by'; then
  die 14 "该文件由配置管理工具托管，请改到你们的配置仓库"
fi
say "  预检通过"

say "[2/5] 备份"
BACKUP="$TARGET.p2s.bak.$(date +%Y%m%d-%H%M%S)"
cp -p "$TARGET" "$BACKUP" || die 20 "备份失败"
say "  已备份到 $BACKUP"

say "[3/5] 应用变更"
apply_kv() {{
  K="$1"; V="$2"
  if grep -qE "^[[:space:]]*$K[[:space:]]*=" "$TARGET"; then
    sed -i "s|^[[:space:]]*$K[[:space:]]*=.*|$K = $V|" "$TARGET"
  elif grep -qE "^[[:space:]]*;[[:space:]]*$K[[:space:]]*=" "$TARGET"; then
    sed -i "s|^[[:space:]]*;[[:space:]]*$K[[:space:]]*=.*|$K = $V|" "$TARGET"
  else
    printf '\\n; === 由见微 Pinpoint 加固 %s ===\\n%s = %s\\n' "$(date +%F)" "$K" "$V" >> "$TARGET"
  fi
  say "  $K = $V"
}}
{apply_lines}

say "[4/5] 校验生效值"
VERIFY_FAIL=0
verify_kv() {{
  K="$1"; V="$2"
  if [ "$TARGET_IS_CLI" = "1" ]; then
    GOT=$("$PHP_BIN" -r "echo ini_get('$K');" 2>/dev/null | tr -d '\n')
    SRC="runtime"
  else
    GOT=$(grep -E "^[[:space:]]*$K[[:space:]]*=" "$TARGET" | head -1 | sed 's/^[^=]*=[[:space:]]*//' | tr -d ' \r')
    SRC="file"
  fi
  if [ "$GOT" = "$V" ]; then say "  [$K] $GOT OK ($SRC)"
  else say "  [$K] $GOT != $V ($SRC)"; VERIFY_FAIL=1; fi
}}
{verify_lines}
if [ "$VERIFY_FAIL" -ne 0 ]; then
  say "  校验未通过，自动回滚"
  cp -p "$BACKUP" "$TARGET"
  die 30 "已回滚到 $BACKUP"
fi

AFTER_SHA=$(sha256sum "$TARGET" | cut -d' ' -f1)
STAMP=$(date +%Y%m%d-%H%M%S)
RECEIPT="/tmp/p2s-harden-receipt-$STAMP.json"
{{
  printf 'after_sha=%s\nbackup=%s\napplied=%s\n' "$AFTER_SHA" "$BACKUP" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > "$TARGET.p2s.state" 2>/dev/null || say "  [WARN] 状态文件写入失败，回滚将失去冲突检查"
  chmod 600 "$TARGET.p2s.state" 2>/dev/null || true
  printf '{{"host":"%s","target":"%s","before_sha":"%s","after_sha":"%s","backup":"%s",' \\
    {_q(host)} "$TARGET" "$EXPECT_SHA" "$AFTER_SHA" "$BACKUP"
  printf '"applied":['
  FIRST=1
  emit() {{ if [ "$FIRST" = 1 ]; then FIRST=0; else printf ','; fi; printf '{{"key":"%s","value":"%s"}}' "$1" "$2"; }}
{emit_lines}
  printf '],"token":"%s","at":"%s","runtime_verified":false}}\\n' "$TOKEN" "$(date +%Y-%m-%dT%H:%M:%S)"
}} > "$RECEIPT"

say "[5/5] 完成"
say "  回执：$RECEIPT"
say "  把该文件内容贴回平台「加固回执」即完成闭环"
{reload_block}"""

    rollback = f"""#!/bin/sh
# 回滚脚本 —— 把 php.ini 恢复到加固前
# 与加固脚本配套：加固成功后会写 <目标>.p2s.state，记录"加固后"的 sha。
# 回滚前先比对当前文件是否仍等于"加固后"的 sha：
#   · 相等 -> 说明加固后没人动过，可以安全回滚
#   · 不等 -> 说明加固后又有人改过（可能是业务调整），直接覆盖会抹掉别人的改动
set -eu
TARGET={_q(target)}
EXPECT_SHA={_q(before_sha)}
FORCE=0
if [ "$#" -gt 0 ] && [ "$1" = "--force" ]; then FORCE=1; fi
STATE="$TARGET.p2s.state"
BACKUP=$(ls -t "$TARGET".p2s.bak.* 2>/dev/null | head -1)
if [ -z "$BACKUP" ]; then echo "[FAIL] 找不到备份文件" >&2; exit 10; fi

if [ -f "$STATE" ] && [ "$FORCE" = "0" ]; then
  EXPECT_AFTER=$(sed -n 's/^after_sha=//p' "$STATE" | head -1)
  NOW=$(sha256sum "$TARGET" | cut -d' ' -f1)
  if [ -n "$EXPECT_AFTER" ] && [ "$NOW" != "$EXPECT_AFTER" ]; then
    echo "[FAIL] 回滚已中止：目标文件在加固之后被修改过。" >&2
    echo "       加固后记录: $EXPECT_AFTER" >&2
    echo "       当前文件  : $NOW" >&2
    echo "       直接覆盖会抹掉这些改动。确认要放弃它们，请执行：" >&2
    echo "         sudo sh rollback.sh --force" >&2
    exit 31
  fi
fi

cp -p "$BACKUP" "$TARGET"
NOW=$(sha256sum "$TARGET" | cut -d' ' -f1)
if [ -n "$EXPECT_SHA" ] && [ "$NOW" != "$EXPECT_SHA" ]; then
  echo "[WARN] 回滚后 sha 与加固前记录不一致：$NOW" >&2
fi
rm -f "$STATE"
echo "[OK] 已从 $BACKUP 回滚；记得重启 PHP 服务"
"""

    diff_lines = ["# 预期的 php.ini 变更（由平台按当前生效值推算）", f"# 文件: {target}", ""]
    for a in actions:
        diff_lines.append(f"-{a['key']} = {a['from']}")
        diff_lines.append(f"+{a['key']} = {a['value']}")
        diff_lines.append("")

    manifest = {
        "generated_at": ts,
        "host": host,
        "target": target,
        "before_sha256": before_sha,
        "token": token,
        "actions": actions,
        "allowed_actions": list(ACTION_WHITELIST),
        "preflight": [
            "目标文件存在且可写",
            "非容器环境（/.dockerenv 不存在）",
            "文件 sha256 与平台记录一致",
            "未被 Ansible/Puppet/Salt 托管",
        ],
        "rollback": "rollback.sh [--force]（使用 .p2s.bak.<时间戳> 备份，默认做冲突检查）",
        # 存储态写入成功不等于运行时生效：与安天工具一致，显式标出
        "runtime_verified": False,
        "discipline": {
            "reject_symlink": 15, "reject_hardlink": 16,
            "reject_group_writable": 17, "reject_duplicate": 18,
            "reject_continuation": 19, "rollback_conflict": 31,
        },
        "receipt_required": True,
    }

    svc_hint = ("php8.3-fpm" if "/8.3/" in target else
                "php8.2-fpm" if "/8.2/" in target else
                "php8.4-fpm" if "/8.4/" in target else
                "php8.5-fpm" if "/8.5/" in target else "php-fpm")
    readme = f"""加固包说明（由见微 Pinpoint 生成 · 平台不会远程执行任何命令）
================================================================

主机     : {host}
目标文件 : {target}
生成时间 : {ts}
影响范围 : 使用该 php.ini 的 PHP 进程；改完必须重启对应服务才生效

一、先看变更
------------
    type diff.patch

确认下面的键确实要改，再往下走。

二、执行（需要 root / 管理员）
-----------------------------
    sudo sh harden.sh

脚本会依次做：
  1) 预检 —— 文件存在可写、非容器、sha256 与平台记录一致、未被 Ansible/Puppet/Salt 托管；
     任何一项不过就退出，**不会改文件**；
  2) 备份 —— 同目录生成 php.ini.p2s.bak.<时间戳>；
  3) 写入 —— 只做 ini 键值替换/追加，不执行其他命令；
  4) 校验 —— 按目标类型核对：cli 用运行时值，fpm/apache 用文件内容；
     校验不过会**自动回滚**并退出；
  5) 回执 —— 生成 /tmp/p2s-harden-receipt-<时间戳>.json。

三、让改动生效
--------------
    sudo systemctl reload {svc_hint}      # FPM 场景
    sudo systemctl reload apache2         # mod_php 场景

四、确认生效（在目标机执行）
--------------------------
    php -i | grep -E 'upload_progress|use_strict_mode'
    # 或访问站点页，用 phpinfo()/ini_get() 看实际值

五、回滚
--------
    sudo sh rollback.sh
（使用最近一次 .p2s.bak.<时间戳> 备份）

六、必须知道的边界
------------------
- **存储态写入成功不等于运行时生效**：回执里 runtime_verified 恒为 false，
  必须重启服务并用 phpinfo / 业务请求确认真实生效（见第四节）；
- 回滚默认做冲突检查：若加固后有人改过文件，回滚会中止（退出码 31），
  确认要放弃那些改动才加 --force；
------------------
- 关闭 session.upload_progress **只是减少攻击面**，不是修复漏洞；
  CVE-2026-109618 的 OOM 路径位于 Zend 引擎核心，**唯一完整修复是升级 PHP**；
- 若该机器由 Ansible/Puppet/Salt/Chef 管理，请把变更写进你们的配置仓库，
  不要用本脚本（下次 converge 会被覆盖，且平台无法感知原因）；
- 容器里的 PHP 不要改容器内文件，请改用 compose 挂载 php.ini 或换镜像。

七、回执样例
------------
{{"host":"{host}","target":"{target}","before_sha":"…","after_sha":"…",
 "applied":[{{"key":"session.upload_progress.enabled","value":"0"}}],"at":"…"}}
把整段 JSON 贴回平台「加固回执」即可完成闭环。
"""
    return {
        "harden.sh": harden,
        "rollback.sh": rollback,
        "diff.patch": "\n".join(diff_lines),
        "manifest.json": json.dumps(manifest, ensure_ascii=False, indent=2),
        "README.txt": readme,
    }
