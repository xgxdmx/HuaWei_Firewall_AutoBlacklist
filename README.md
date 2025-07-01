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
- paramiko>=3.5.0
- cryptography>=44.0.1
- PyNaCl>=1.5.0
- bcrypt>=4.3.0
                 
---

## 🚀 运行

1. 安装依赖库：

    执行命令：`pip install -r requirements.txt`
2. 配置参数：

    编辑AutoBlacklist.py文件，将参数配置为实际值。

| 参数名 | 描述 |
|--------|------|
| `FIREWALL_IP` | 华为 USG 防火墙的 IP 地址 |
| `SSH_PORT` | SSH 端口号，默认为 `22` |
| `USERNAME` | 登录防火墙的用户名 |
| `PASSWORD` | 登录防火墙的密码（可选，推荐使用密钥） |
| `KEY_FILE_PATH` | SSH 私钥路径（如使用密钥登录） |
| `IP_THRESHOLD` | 触发封禁的威胁源 IP 出现次数阈值 |
| `FIREWALL_BLOCK_TIME` | 封禁时长（单位：分钟），默认 `300` |

3. 运行脚本：

    执行命令：`python AutoBlacklist.py`

4. 查看日志：

    - 所有操作记录将写入 firewall_check.log
    - 被封禁的 IP 地址记录在 blocked_ips.log

5. 设置定时任务（可选）

    使用corntab或定时任务面板设置定时任务

    例如每五分钟执行一次脚本

    `*/5 * * * * /usr/bin/python ./AutoBlacklist.py`
