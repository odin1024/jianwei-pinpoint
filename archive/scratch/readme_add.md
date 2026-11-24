### 2.3 设备发现（推荐先跑这个）

```powershell
# 单台
python -m p2s.cli discover --host 192.168.1.229 --report reports\

# 网段批量（最多 1024 台）
python -m p2s.cli discover --cidr 192.168.1.0/24 --report reports\
```

输出示例：

```
发现完成 [disc-b6ad8f1cc9]  目标=2
  设备类型分布: 堡垒机 / 运维审计×1  Web 服务器（无 PHP）×1
  [ ] 192.168.1.229           堡垒机 / 运维审计             PHP=无 暴露=not_php 置信=0.87
        端口: [25, 110, 143, 443, 2000, 10000]
        · TLS 证书: CN=server,OU=yanfa,O=jump
        · Server 头: Jump_server
        · 页面标题: 开发测试防火墙系统
  [ ] 192.168.1.188           Web 服务器（无 PHP）          PHP=无 暴露=not_php 置信=0.77
        端口: [22, 25, 80, 110, 143, 3389, 8080, 8088]
        · SSH banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20
```

### 2.4 Web 控制台的九个页面

| 页面 | 作用 |
|---|---|
| **态势总览** | KPI 卡 + PHP 暴露面环形图 + 设备类型分布条形图 + 最近扫描 |
| **设备发现** | 网段/批量主机发现，设备卡片网格，点开看完整画像 |
| **资产台账** | 设备画像持久化，按暴露面筛选、搜索、CSV 导出、复扫 |
| **PHP 暴露面** | 只列真正跑 PHP 的资产，版本 vs 修复基线矩阵 + 处置建议 |
| **日志分析** | 被动检测，命中明细 + **规则覆盖缺口**提示 |
| **主机侧检测** | 本机 PHP 安装点、生效配置、可疑痕迹 |
| **规则中心** | 13 条规则，一键导出 Sigma / ModSecurity / Suricata |
| **IOC 中心** | 攻击者基础设施、dropper URL、样本哈希 |
| **报告中心** | 历史扫描，JSON / Markdown / HTML 三份报告下载 |

界面支持**浅色 / 深色切换**（右上角 ◐ 按钮，选择记在 localStorage）。