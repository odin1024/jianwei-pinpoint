"""测试全局配置：在导入 p2s 之前把数据目录与口令固定下来。

控制台模块在 import 时就会创建数据目录并构造 JobManager，
因此必须在任何 `from p2s...` 之前设置环境变量。
"""
import os
import tempfile

import pytest

os.environ["P2S_DATA_DIR"] = tempfile.mkdtemp(prefix="p2s-test-")
# 强制覆盖，不用 setdefault：开发者 shell 里导出的真实口令/令牌不能影响测试
os.environ["P2S_CONSOLE_PASSWORD"] = "test-pass"
os.environ["P2S_AGENT_TOKEN"] = "test-agent-token"


@pytest.fixture(scope="session")
def client():
    """未登录的客户端（follow_redirects=False，便于断言 302）。"""
    from fastapi.testclient import TestClient

    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        yield c


@pytest.fixture(scope="session")
def auth_client(client):
    """已登录的客户端，供各测试模块共用。"""
    r = client.post("/api/login", json={"password": "test-pass"})
    assert r.status_code == 200, r.text
    return client
