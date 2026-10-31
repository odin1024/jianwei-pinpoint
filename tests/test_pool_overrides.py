"""pool 级 php_admin_value 解析测试。"""
from __future__ import annotations

from p2s.console.agent_api import _parse_pool_overrides


def test_extracts_real_override():
    raw = ("/etc/php/8.3/fpm/pool.d/www.conf:"
           "php_admin_value[session.use_strict_mode] = 0")
    got = _parse_pool_overrides(raw)
    assert got == [{"path": "/etc/php/8.3/fpm/pool.d/www.conf",
                    "key": "session.use_strict_mode", "value": "0"}]


def test_skips_commented_default():
    """DejaVu 默认 www.conf 里全是注释行，不能算覆盖。"""
    raw = ("/etc/php/8.3/fpm/pool.d/www.conf:"
           ";php_admin_value[error_log] = /var/log/fpm-php.www.log")
    assert _parse_pool_overrides(raw) == []


def test_ignores_unrelated_keys():
    raw = "/etc/php-fpm.d/www.conf:php_value[post_max_size] = 64M"
    assert _parse_pool_overrides(raw) == []


def test_handles_quoted_value():
    raw = ('/etc/php/8.3/fpm/pool.d/a.conf:'
           'php_admin_value[display_errors] = "Off"')
    got = _parse_pool_overrides(raw)
    assert got and got[0]["value"] == "Off"


def test_empty_input():
    assert _parse_pool_overrides("") == []
    assert _parse_pool_overrides(None) == []
