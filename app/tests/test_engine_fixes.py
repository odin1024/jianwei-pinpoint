"""引擎层回归测试：探针分发、banner 协议判定、任务字典字段。"""
from __future__ import annotations

import http.server
import socketserver
import threading

import pytest


class _Recorder(http.server.BaseHTTPRequestHandler):
    """记录收到的 POST 请求体大小，用于验证探针真的发出去了。"""

    hits: list[int] = []

    def log_message(self, *args):  # noqa: D102
        pass

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        type(self).hits.append(n)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture()
def echo_server():
    _Recorder.hits = []
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Recorder)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()


def test_gentle_probe_actually_sends_payload(echo_server):
    """v0.5.0 的 bug：probe_once('gentle') 落到 else 分支直接返回，只发了一个控制请求。"""
    from p2s.core.probe import probe_once

    r = probe_once(echo_server, "gentle", timeout=5)
    assert r.notes == [], r.notes
    assert r.status_code == 200
    assert r.payload_bytes > 0
    assert len(_Recorder.hits) == 2, _Recorder.hits
    control, probe = _Recorder.hits
    assert probe > control * 10, f"探针应显著大于控制请求：{control} vs {probe}"


def test_unknown_probe_is_rejected(echo_server):
    from p2s.core.probe import probe_once

    r = probe_once(echo_server, "nope", timeout=5)
    assert r.status_code is None
    assert any("未知探针" in n for n in r.notes)


def test_assess_runs_probe(echo_server):
    from p2s.core import probe as probe_mod

    asm = probe_mod.assess(echo_server, timeout=5, do_probe=True)
    assert asm.probes, "assess 必须留下探测记录"
    assert asm.probes[0].payload_bytes > 0


# --------------------------------------------------------------------------
# banner 协议判定
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "banner,port,expected",
    [
        ("220-FileZilla Server 中文版 0.9.60 beta\r\n220 Please visit https://filezilla-project.org/", 21, "ftp"),
        ("220 mail.example.com ESMTP Postfix", 25, "smtp"),
        ("220 ESMTP ready", 587, "smtp"),
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20", 22, "ssh"),
        ("+OK Dovecot ready.", 110, "ftp"),
        ("* OK IMAP4rev1 ready", 143, "imap"),
        ("\x00\x01\x02binary", 9999, "tcp"),
    ],
)
def test_guess_proto(banner, port, expected):
    from p2s.core.discovery import _guess_proto

    assert _guess_proto(banner, port) == expected


# --------------------------------------------------------------------------
# 任务字典必须带 active（前端「运行中任务」KPI 依赖它）
# --------------------------------------------------------------------------
def test_job_to_dict_has_active(tmp_path):
    """active 是 property，asdict() 不会带出来；前端 KPI 依赖它。"""
    import threading

    from p2s.core.jobs import JobManager

    gate = threading.Event()
    jm = JobManager(tmp_path, max_workers=1)
    job = jm.submit("host", "t", lambda j, p: (gate.wait(5), {"ok": True})[1])
    try:
        d = job.to_dict()
        assert "active" in d
        assert d["active"] is True
    finally:
        gate.set()
        jm._pool.shutdown(wait=True)


def test_jobs_persist_is_atomic(tmp_path):
    from p2s.core.jobs import JobManager

    jm = JobManager(tmp_path, max_workers=1)
    jm.submit("host", "t", lambda j, p: {"ok": True})
    # 不应留下半截临时文件
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []
