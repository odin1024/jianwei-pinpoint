"""容器内 PHP 清点测试：解析逻辑用离线样本，不依赖真实 docker。"""
from __future__ import annotations

import pytest

from p2s.core import containers as c


@pytest.mark.parametrize("image,ver,sapi", [
    ("php:8.1-fpm", "8.1", "fpm-fcgi"),
    ("php:8.4.27-apache", "8.4.27", "apache2handler"),
    ("php:8.3-cli", "8.3", "cli"),
    ("wordpress:6.2-php8.1", "8.1", None),
    ("library/php:8.2-fpm-alpine", "8.2", "fpm-fcgi"),
])
def test_parse_version_from_image(image, ver, sapi):
    got_v, got_s = c.parse_php_from_image(image)
    assert got_v == ver
    if sapi:
        assert got_s == sapi


def test_non_php_image_ignored():
    for img in ("nginx:1.25", "redis:7", "mysql:8.0", "mycompany/app:1.0"):
        assert c.parse_php_from_image(img) == (None, None)


def test_php_image_without_version():
    ver, sapi = c.parse_php_from_image("php:fpm")
    assert ver is None and sapi == "fpm-fcgi"


def test_scan_without_docker_is_graceful(monkeypatch):
    monkeypatch.setattr(c, "docker_available", lambda: False)
    installs, notes = c.scan_containers()
    assert installs == []
    assert any("docker" in n for n in notes)


def test_scan_with_fake_containers(monkeypatch):
    monkeypatch.setattr(c, "docker_available", lambda: True)
    monkeypatch.setattr(c, "list_containers", lambda: [
        {"id": "a", "image": "php:8.1-fpm", "name": "web-php"},
        {"id": "b", "image": "redis:7", "name": "cache"},
        {"id": "c", "image": "wordpress:6.2-php8.0", "name": "blog"},
    ])
    installs, notes = c.scan_containers()
    names = {i.container for i in installs}
    assert names == {"web-php", "blog"}          # redis 被正确忽略
    assert notes == []
    d = [i.to_dict() for i in installs]
    assert all(x["path"].startswith("container:") for x in d)
    assert {x["version"] for x in d} == {"8.1", "8.0"}
