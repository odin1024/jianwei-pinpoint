"""R-03 跨主机噪声端口 + R-07 资产变化检测。"""
from __future__ import annotations


def _profile(host: str, ports: list[int], meaningful: list[int] | None = None, alive: bool = True):
    from p2s.core.discovery import DeviceProfile

    p = DeviceProfile(host=host, alive=alive)
    p.open_ports = list(ports)
    p.meaningful_ports = list(meaningful or [])
    p.noise_ports = []
    p.evidence = []
    return p


# --------------------------------------------------------------------------
# R-03
# --------------------------------------------------------------------------
def test_noise_ports_removed_across_hosts():
    """同一组端口在整片网段都"可连但无响应"，应被剔除；真正有响应的端口要保留。"""
    from p2s.core.identification import apply_noise_ports

    profiles = [_profile(f"10.0.0.{i}", [25, 110, 143]) for i in range(6)]
    profiles[0].open_ports = [25, 80, 110, 143]
    profiles[0].meaningful_ports = [80]

    noise = apply_noise_ports(profiles)

    assert {25, 110, 143} <= noise
    assert profiles[0].open_ports == [80], "有有效响应的 80 不能被剔除"
    assert profiles[1].open_ports == []
    assert {25, 110, 143} <= set(profiles[1].noise_ports), profiles[1].noise_ports
    assert any("噪声" in e for e in profiles[1].evidence)


def test_noise_ports_need_enough_samples():
    """少于 5 台时不做跨主机判断，避免小样本误伤。"""
    from p2s.core.identification import apply_noise_ports

    profiles = [_profile(f"10.0.0.{i}", [25, 110, 143]) for i in range(4)]
    assert apply_noise_ports(profiles) == set()
    assert profiles[0].open_ports == [25, 110, 143]


def test_noise_ports_skip_offline_hosts():
    from p2s.core.identification import apply_noise_ports

    profiles = [_profile(f"10.0.0.{i}", [25, 110], alive=False) for i in range(8)]
    assert apply_noise_ports(profiles) == set()


def test_common_but_meaningful_port_is_not_noise():
    """80 端口在整片网段都开着，但多数主机有 HTTP 响应 → 不能算噪声。

    这是本轮初版实现的坑：只统计「开着的端口」，把 22/80/443 一起剔了。
    """
    from p2s.core.identification import apply_noise_ports

    profiles = []
    for i in range(6):
        p = _profile(f"10.0.1.{i}", [25, 80, 110, 143])
        p.meaningful_ports = [80] if i < 5 else []      # 5/6 有真实 HTTP 响应
        profiles.append(p)

    noise = apply_noise_ports(profiles)

    assert 80 not in noise
    assert all(80 in p.open_ports for p in profiles), "有响应的 80 不该被剔除"
    assert {25, 110, 143} <= noise


# --------------------------------------------------------------------------
# R-07
# --------------------------------------------------------------------------
def test_diff_asset_new_changed_same():
    from p2s.console.deps import _diff_asset

    new = {"exposure": "not_php", "php_version": None, "risk": "low"}
    assert _diff_asset(None, new)["kind"] == "new"

    old = {"exposure": "not_php", "php_version": None, "risk": "low"}
    assert _diff_asset(old, dict(new)) is None

    later = dict(new, exposure="exposed", php_version="8.4.26")
    diff = _diff_asset(old, later)
    assert diff["kind"] == "changed"
    assert diff["fields"]["exposure"] == ["not_php", "exposed"]
    assert diff["fields"]["php_version"] == [None, "8.4.26"]


def test_overview_exposes_changes(auth_client):
    o = auth_client.get("/api/overview").json()
    assert set(o["changes"]) == {"new", "changed", "gone"}
    assert isinstance(o["recent_changes"], list)
    assert all("host" in c and "kind" in c for c in o["recent_changes"])


def test_scan_result_carries_changes():
    from p2s.core.report import ScanResult

    r = ScanResult(scan_id="x", kind="discover", started_at="t")
    r.changes = [{"host": "10.0.0.1", "kind": "new", "at": "t"}]
    assert r.to_dict()["changes"][0]["kind"] == "new"

