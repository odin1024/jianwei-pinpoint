-- ============================================================
-- P2S-Guard 数据库 Schema
-- 兼容：SQLite 3.35+ / PostgreSQL 14+
-- 说明：
--   1. 本文件以 SQLite 语法为主，PostgreSQL 差异处用注释标注 [PG]
--   2. 所有时间字段统一存 UTC（ISO8601 字符串 / [PG] timestamptz）
--   3. 敏感字段（credentials.cipher、evidence.raw_enc）为密文，密钥外置
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------
-- 1. 资产
-- ------------------------------------------------------------
CREATE TABLE asset (
    id              TEXT PRIMARY KEY,              -- ast_xxxx
    name            TEXT NOT NULL,
    type            TEXT NOT NULL                  -- url | host | cidr_host | image | firmware
                    CHECK (type IN ('url','host','cidr_host','image','firmware')),
    business_unit   TEXT,
    owner           TEXT,                          -- 责任人
    exposure        TEXT NOT NULL DEFAULT 'internal'
                    CHECK (exposure IN ('internet','internet_waf','internal','ops_only','unknown')),
    criticality     INTEGER NOT NULL DEFAULT 3,    -- 1(低) - 5(高)
    tags            TEXT,                          -- JSON array
    source          TEXT,                          -- import | manual | api | discovery
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT
);
CREATE INDEX idx_asset_exposure ON asset(exposure);
CREATE INDEX idx_asset_owner ON asset(owner);

CREATE TABLE asset_endpoint (
    id              TEXT PRIMARY KEY,
    asset_id        TEXT NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    scheme          TEXT,                          -- http | https | ssh | winrm
    host            TEXT NOT NULL,
    port            INTEGER,
    path            TEXT,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    last_seen_at    TEXT
);
CREATE INDEX idx_endpoint_asset ON asset_endpoint(asset_id);
CREATE UNIQUE INDEX uq_endpoint ON asset_endpoint(asset_id, scheme, host, port, IFNULL(path,''));

-- ------------------------------------------------------------
-- 2. 任务与编排
-- ------------------------------------------------------------
CREATE TABLE task (
    id              TEXT PRIMARY KEY,              -- tsk_xxxx
    name            TEXT NOT NULL,
    profile         TEXT NOT NULL DEFAULT 'standard'
                    CHECK (profile IN ('passive','standard','deep','forensic')),
    status          TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','QUEUED','RUNNING','PAUSED','PARTIAL','SUCCEEDED','FAILED','ABORTED')),
    detectors       TEXT,                          -- JSON array: ["D1","D2",...]
    safety          TEXT,                          -- JSON: {allow_intrusive,qps,...}
    ruleset_version TEXT NOT NULL,
    total_units     INTEGER DEFAULT 0,
    done_units      INTEGER DEFAULT 0,
    failed_units    INTEGER DEFAULT 0,
    authorization_ref TEXT,                        -- 授权凭据（工单号/合同号）
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    error_summary   TEXT
);
CREATE INDEX idx_task_status ON task(status, created_at DESC);

CREATE TABLE shard (
    id              TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'PENDING',
    worker_id       TEXT,
    started_at      TEXT,
    finished_at     TEXT
);
CREATE INDEX idx_shard_task ON shard(task_id, seq);

CREATE TABLE unit (
    id              TEXT PRIMARY KEY,
    shard_id        TEXT NOT NULL REFERENCES shard(id) ON DELETE CASCADE,
    task_id         TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (state IN ('PENDING','RUNNING','DONE','FAILED','SKIPPED','ABORTED')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    checkpoint      TEXT,                          -- JSON: 已完成阶段
    error           TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    UNIQUE (task_id, asset_id)
);
CREATE INDEX idx_unit_state ON unit(task_id, state);

-- ------------------------------------------------------------
-- 3. 结果与证据
-- ------------------------------------------------------------
CREATE TABLE scan_result (
    id              TEXT PRIMARY KEY,              -- res_xxxx
    unit_id         TEXT NOT NULL REFERENCES unit(id) ON DELETE CASCADE,
    task_id         TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    vuln_id         TEXT NOT NULL DEFAULT 'php2shell',
    verdict         TEXT NOT NULL
                    CHECK (verdict IN ('vulnerable','likely_vulnerable','patched','not_applicable','unknown')),
    confidence      TEXT NOT NULL
                    CHECK (confidence IN ('confirmed','high','medium','low','unknown')),
    risk_score      INTEGER NOT NULL DEFAULT 0,    -- 0-100
    grade           TEXT NOT NULL DEFAULT 'P3' CHECK (grade IN ('P0','P1','P2','P3','NONE')),
    factors         TEXT,                          -- JSON: 各因子取值
    reason          TEXT,                          -- 人类可读结论
    needs_review    INTEGER NOT NULL DEFAULT 0,    -- 证据冲突标记
    effective       INTEGER NOT NULL DEFAULT 1,    -- 补丁是否已生效（worker 是否重启）
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_result_asset ON scan_result(asset_id, created_at DESC);
CREATE INDEX idx_result_verdict ON scan_result(task_id, verdict, risk_score DESC);

CREATE TABLE evidence (
    id              TEXT PRIMARY KEY,
    result_id       TEXT NOT NULL REFERENCES scan_result(id) ON DELETE CASCADE,
    detector        TEXT NOT NULL,                 -- D1..D7
    kind            TEXT NOT NULL,                 -- version|sapi|ini|changelog|binary|source|log|file|process|behavior
    key             TEXT NOT NULL,                 -- php.version / php.sapi / ini.memory_limit ...
    value_text      TEXT,                          -- 归一化后的值（明文，非敏感）
    value_json      TEXT,                          -- 结构化值
    confidence      TEXT NOT NULL,
    method          TEXT,                          -- 采集方法描述
    source_ref      TEXT,                          -- 原始出处：命令 / 日志行号 / 文件路径
    raw_enc         BLOB,                          -- 原始内容（加密，可能含敏感信息）
    weight          REAL NOT NULL DEFAULT 1.0,
    collected_at    TEXT NOT NULL
);
CREATE INDEX idx_evidence_result ON evidence(result_id);
CREATE INDEX idx_evidence_key ON evidence(result_id, kind, key);

-- ------------------------------------------------------------
-- 4. 漏洞知识库与指纹
-- ------------------------------------------------------------
CREATE TABLE vulnerability (
    id              TEXT PRIMARY KEY,              -- php2shell
    name            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cvss_v4         REAL,
    cvss_v3         REAL,
    cve_ids         TEXT,                          -- JSON array
    ghsa_ids        TEXT,
    summary         TEXT,
    published_at    TEXT,
    updated_at      TEXT
);

CREATE TABLE vuln_version_range (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id         TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
    branch          TEXT NOT NULL,                 -- "8.4" / "8.1" / "<=8.0"
    affected_expr   TEXT NOT NULL,                 -- "<8.4.27" / "*"
    fixed_version   TEXT,                          -- null 表示无修复
    eol             INTEGER NOT NULL DEFAULT 0,
    support_until   TEXT,                          -- 安全支持到期日
    note            TEXT
);

CREATE TABLE vuln_sapi (
    vuln_id         TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
    sapi            TEXT NOT NULL,                 -- apache2handler | fpm-fcgi | frankenphp ...
    exploitable     TEXT NOT NULL,                 -- confirmed | likely | possible | none | unknown
    app_independent INTEGER NOT NULL DEFAULT 0,
    weight          REAL NOT NULL DEFAULT 0.5,
    note            TEXT,
    PRIMARY KEY (vuln_id, sapi)
);

CREATE TABLE patch_fingerprint (
    id              TEXT PRIMARY KEY,
    vuln_id         TEXT NOT NULL,
    distro          TEXT,                          -- rhel9 | ubuntu2204 | alpine3.19 | kylin10 | official
    package_name    TEXT,
    package_version TEXT,
    binary_path     TEXT,
    build_id        TEXT,
    sha256          TEXT,
    has_patch       INTEGER NOT NULL,
    markers_patched TEXT,                          -- JSON array of hex
    markers_vulnerable TEXT,                       -- JSON array of hex
    source_url      TEXT,
    verified_at     TEXT,
    verified_by     TEXT
);
CREATE INDEX idx_fp_sha ON patch_fingerprint(sha256);

-- ------------------------------------------------------------
-- 5. 失陷排查
-- ------------------------------------------------------------
CREATE TABLE hunt_session (
    id              TEXT PRIMARY KEY,
    asset_id        TEXT REFERENCES asset(id),
    host            TEXT NOT NULL,
    window_start    TEXT NOT NULL,                 -- 默认 2026-10-17T00:00:00Z
    window_end      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'CREATED'
                    CHECK (status IN ('CREATED','INGESTING','ANALYZING','DONE','FAILED')),
    overall_verdict TEXT,                          -- clean | suspicious | compromised | inconclusive
    confidence      TEXT,
    stats           TEXT,                          -- JSON: 请求数/错误数/命中规则数
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    finished_at     TEXT
);

CREATE TABLE hunt_finding (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES hunt_session(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,                 -- HUNT-001 ...
    rule_name       TEXT,
    confidence      TEXT NOT NULL,
    occurred_at     TEXT,
    src_ip          TEXT,
    method          TEXT,
    uri             TEXT,
    status_code     INTEGER,
    matched_line    TEXT,                          -- 脱敏后的原始行
    log_file        TEXT,
    line_no         INTEGER,
    detail          TEXT,
    correlated_with TEXT                           -- JSON: 关联的其他 finding id
);
CREATE INDEX idx_hunt_finding_session ON hunt_finding(session_id, occurred_at);

-- ------------------------------------------------------------
-- 6. 处置
-- ------------------------------------------------------------
CREATE TABLE remediation (
    id              TEXT PRIMARY KEY,
    result_id       TEXT NOT NULL REFERENCES scan_result(id) ON DELETE CASCADE,
    action          TEXT NOT NULL,                 -- upgrade | migrate | temp_mitigation | offline | restrict
    target_version  TEXT,
    items           TEXT,                          -- JSON: 具体步骤
    is_complete     INTEGER NOT NULL DEFAULT 0,    -- 是否为完整修复
    risk_note       TEXT,                          -- 副作用提示（如 RLIMIT 禁用警告）
    priority        INTEGER NOT NULL DEFAULT 3,
    status          TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN','IN_PROGRESS','DONE','VERIFIED','FAILED','ACCEPTED_RISK')),
    assignee        TEXT,
    due_at          TEXT,
    verified_at     TEXT,
    verify_result_id TEXT                          -- 复扫结果
);
CREATE INDEX idx_remediation_status ON remediation(status, priority);

-- ------------------------------------------------------------
-- 7. 规则管理
-- ------------------------------------------------------------
CREATE TABLE ruleset (
    version         TEXT PRIMARY KEY,              -- 2026.10.28-1
    checksum        TEXT NOT NULL,
    signature       TEXT,                          -- Ed25519
    published_at    TEXT,
    loaded_at       TEXT NOT NULL,
    active          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE rule (
    id              TEXT PRIMARY KEY,
    ruleset_version TEXT NOT NULL REFERENCES ruleset(version) ON DELETE CASCADE,
    category        TEXT NOT NULL,                 -- detect | hunt | patch
    name            TEXT NOT NULL,
    severity        TEXT,
    content         TEXT NOT NULL,                 -- YAML 原文
    enabled         INTEGER NOT NULL DEFAULT 1
);

-- ------------------------------------------------------------
-- 8. 凭证（加密）
-- ------------------------------------------------------------
CREATE TABLE credential (
    id              TEXT PRIMARY KEY,
    asset_id        TEXT REFERENCES asset(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('ssh_password','ssh_key','winrm','api_token')),
    username        TEXT,
    cipher          BLOB NOT NULL,                 -- AES-256-GCM
    nonce           BLOB NOT NULL,
    kms_key_id      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_used_at    TEXT
);

-- ------------------------------------------------------------
-- 9. 平台：用户 / 角色 / 审计
-- ------------------------------------------------------------
CREATE TABLE app_user (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT,
    password_hash   TEXT NOT NULL,                 -- argon2id
    mfa_secret_enc  BLOB,
    status          TEXT NOT NULL DEFAULT 'ACTIVE'
                    CHECK (status IN ('ACTIVE','DISABLED','LOCKED')),
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

CREATE TABLE role (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,          -- admin | operator | auditor | viewer
    description     TEXT
);

CREATE TABLE user_role (
    user_id         TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE permission (
    id              TEXT PRIMARY KEY,
    code            TEXT NOT NULL UNIQUE,          -- task:create / report:export / rule:update ...
    description     TEXT
);

CREATE TABLE role_permission (
    role_id         TEXT NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    permission_id   TEXT NOT NULL REFERENCES permission(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 审计日志：哈希链，防篡改
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    target          TEXT,
    detail          TEXT,
    ip              TEXT,
    prev_hash       TEXT,                          -- 上一条 hash（首条为 64 个 0）
    hash            TEXT NOT NULL,                 -- SHA256(prev_hash || canonical(payload))
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_audit_time ON audit_log(created_at);

-- ------------------------------------------------------------
-- 10. 视图：便于报表与看板
-- ------------------------------------------------------------
CREATE VIEW v_risk_summary AS
SELECT
    a.exposure,
    r.grade,
    COUNT(*) AS cnt
FROM scan_result r
JOIN asset a ON a.id = r.asset_id
WHERE r.created_at >= datetime('now', '-7 days')
GROUP BY a.exposure, r.grade;

CREATE VIEW v_pending_remediation AS
SELECT
    rm.id, rm.action, rm.priority, rm.due_at,
    r.asset_id, r.risk_score, r.grade,
    a.name AS asset_name, a.owner
FROM remediation rm
JOIN scan_result r ON r.id = rm.result_id
JOIN asset a ON a.id = r.asset_id
WHERE rm.status IN ('OPEN','IN_PROGRESS')
ORDER BY rm.priority ASC, r.risk_score DESC;
