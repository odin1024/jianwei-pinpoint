# 反向代理与 TLS 部署

控制台默认只监听 HTTP（内网单机定位）。对外或跨网段访问时，请在前面放一层反向代理做 TLS 终止。

## 一、Nginx 反代示例

```nginx
server {
    listen 443 ssl http2;
    server_name p2s.corp.local;

    ssl_certificate     /etc/pki/p2s.crt;
    ssl_certificate_key /etc/pki/p2s.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Agent 上报体积上限 2MB，日志上传上限 100MB
    client_max_body_size 120m;

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
```

**关键点**

- `client_max_body_size` 必须放开：日志上传默认上限 100MB，否则 413；
- `proxy_read_timeout` 要大于最长扫描（254 台约 12 分钟，但单个请求都很快，300s 足够）；
- 反代后控制台仍只绑 `127.0.0.1`，不直接暴露 18080。

## 二、Agent 脚本里的地址

下载脚本时用 `?base=https://p2s.corp.local` 指定对外地址，否则脚本会内嵌当前访问地址
（若你通过 `127.0.0.1` 打开控制台，脚本里的地址对内网主机不可达）：

```
https://p2s.corp.local/api/agent/download?os=linux&base=https://p2s.corp.local
```

## 三、启动参数

```bash
# 只监听本机（推荐，配反代）
p2s serve --host 127.0.0.1 --port 18080

# 直接对内网提供服务（无 TLS，仅限隔离网络）
p2s serve --host 0.0.0.0 --port 18080
```

## 四、口令与令牌

| 环境变量 | 作用 | 默认 |
|---|---|---|
| `P2S_ADMIN_USER` | 登录用户名 | `admin` |
| `P2S_CONSOLE_PASSWORD` | 控制台口令 | 未设置则随机生成并打印到启动日志 |
| `P2S_ADMIN_PASSWORD` | 登录口令（优先于上者） | 无内置默认，缺省复用控制台口令 |
| `P2S_AGENT_TOKEN` | Agent 上报令牌 | 同登录口令 |
| `P2S_SIGNING_KEY` | 加固令牌 HMAC 密钥 | 数据目录内持久化的随机密钥 |
| `P2S_VERIFY_TLS` | 主动探测是否校验证书 | `0`（内网自签场景），设 `1` 开启校验 |

```bash
export P2S_CONSOLE_PASSWORD='<强口令>'
export P2S_AGENT_TOKEN='<独立随机串>'
p2s serve --host 127.0.0.1 --port 18080
```

## 五、不要做的事

- 不要把 18080 直接暴露到公网；
- 不要用自签证书给浏览器访问（Agent 采集走 HTTP 内网即可，浏览器访问走反代 TLS）；
- 不要在反代上开启请求体缓冲以外的改写（会破坏 `X-P2S-Token`）。
