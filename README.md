# Huawei USG 防火墙黑名单IP自动添加（AutoBlacklist）

这是一个基于 Python 的自动化脚本工具，通过 SSH 连接华为USG防火墙，从 IPS 日志中提取威胁源IP，并根据设定的阈值将高频出现的 IP 自动加入黑名单。

---

## 🔍 功能特性

✅ 支持 SSH 登录华为 USG 防火墙  
✅ 提取 `logbuffer` 中IPS模块的威胁源IP地址  
✅ 根据配置的阈值判断是否封禁  
✅ 封禁命令：`firewall blacklist item source-ip <ip> timeout <FIREWALL_BLOCK_TIME>`，默认封禁300分钟  
✅ 记录日志到 `firewall_check.log` 和 `blocked_ips.log`  
✅ 支持 ECC 加密算法连接（如 `ecdsa-sha2-nistp256`）

---

## 🧰 技术栈

- Python 3.12+
- Paramiko（SSH 连接）
- 正则表达式（IP 提取）
- logging（日志记录）

---

## 📦 依赖库

请先安装以下依赖：
- paramiko>=3.4.0
- cryptography>=42.0.5
- PyNaCl>=1.5.0
