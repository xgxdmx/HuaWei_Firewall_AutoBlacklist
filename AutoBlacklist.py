#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paramiko
import re
from collections import defaultdict
from datetime import datetime
import logging
import sys
import time

# 配置防火墙SSH连接信息
# 防火墙IP
FIREWALL_IP = "xxx.xxx.xxx.xxx"
# 防火墙端口
FIREWALL_PORT = 22
# 防火墙用户名
FIREWALL_USER = "username"
# 防火墙密码
FIREWALL_PASSWORD = "password"
# 威胁IP检测阈值
FIREWALL_THRESHOLD = 10
# 威胁IP封禁时间（分钟）
FIREWALL_BLOCK_TIME = 300


# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_check.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('HuaweiFirewall')

# 防火墙自动黑名单类
class AutoBlacklist:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        self.shell = None

    # 建立防火墙SSH连接
    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False,
                # 适配华为防火墙SSH
                disabled_algorithms={
                    'pubkeys': ['rsa-sha2-*'],  # 禁用所有RSA变体
                    'keys': ['ssh-rsa'],  # 强制使用ECC
                    'kex': ['diffie-hellman-group14-*']  # 使用group-exchange
                }
            )

            # 获取传输层并配置
            transport = self.client.get_transport()
            if transport:
                transport._preferred_keys = ['ecdsa-sha2-nistp256']
                transport._preferred_kex = ['diffie-hellman-group-exchange-sha256']
                transport._preferred_ciphers = ['aes256-ctr']
                transport._preferred_macs = ['hmac-sha2-256']
                transport._preferred_compression = ['zlib']
                transport.set_keepalive(20)
            self.shell = self.client.invoke_shell()
            self._wait_for_prompt()
            logger.info(f"成功连接到防火墙 {self.host}")
            return True
        # 处理连接失败
        except Exception as exception:
            logger.error(f"连接失败: {str(exception)[:200]}")
            return False
    # 等待提示符
    def _wait_for_prompt(self, timeout=5):
        start_time = time.time()
        buffer = b""
        while time.time() - start_time < timeout:
            if self.shell.recv_ready():
                buffer += self.shell.recv(1024)
                if b">" in buffer or b"#" in buffer:
                    return True
            time.sleep(0.1)
        raise TimeoutError("等待提示符超时")

    # 发送命令
    def send_command(self, command, wait_prompt=True):
        try:
            self.shell.send(command + "\n")
            output = b""
            start_time = time.time()

            while time.time() - start_time < 10:  # 10秒超时
                if self.shell.recv_ready():
                    output += self.shell.recv(4096)
                    if not wait_prompt or (b">" in output or b"#" in output):
                        break
                time.sleep(0.1)

            return output.decode('utf-8', errors='ignore').strip()

        except Exception as exception:
            logger.error(f"命令执行失败: {str(exception)[:200]}")
            return None

    # 执行配置命令
    def execute_config_command(self, command):
        try:
            self.send_command("system-view")
            output = self.send_command(command)
            self.send_command("return")
            return output
        except Exception as exception:
            logger.error(f"配置命令执行失败: {str(exception)}")
            return None

    # IP威胁检查
    def single_threat_check(self, threshold=FIREWALL_THRESHOLD):
        if not self.connect():
            return None
        result = {
            'detected_ips': defaultdict(int),
            'blocked_ips': []
        }
        # 开始检查
        try:
            # 获取威胁日志
            log_output = self.send_command("display logbuffer module IPS slot 11")
            if not log_output:
                return result
            # 提取源IP（严格匹配日志格式）
            ip_pattern = re.compile(r"SrcIp=(\d+\.\d+\.\d+\.\d+)")
            ips = ip_pattern.findall(log_output)
            # 统计IP出现次数
            for ip in ips:
                result['detected_ips'][ip] += 1
            # 封禁超过阈值的IP
            for ip, count in result['detected_ips'].items():
                if count > threshold:
                    if self.block_ip(ip):
                        result['blocked_ips'].append(ip)
                        self.log_blocked_ip(ip, count)
            # 返回结果
            return dict(result)
        except Exception as exception:
            logger.error(f"威胁检查失败: {str(exception)}")
            return None
        finally:
            self.disconnect()
    # 封禁指定IP
    def block_ip(self, ip):
        block_cmd = f"firewall blacklist item source-ip {ip} timeout {FIREWALL_BLOCK_TIME}"
        logger.info(block_cmd)
        self.execute_config_command(block_cmd)
        return True
    # 记录封禁IP
    @staticmethod
    def log_blocked_ip(ip, count):
        log_entry = f"{datetime.now()} - Blocked IP: {ip} (Count: {count})\n"
        with open("blocked_ips.log", "a") as f:
            f.write(log_entry)
    # 断开连接
    def disconnect(self):
        if self.client:
            try:
                if self.shell:
                    self.shell.send("quit\n")
                    time.sleep(1)
                self.client.close()
                logger.info("SSH连接已关闭")
            except Exception as exception:
                logger.error(f"断开连接时出错: {str(exception)}")
            finally:
                self.client = None
                self.shell = None

def main():
    # 配置防火墙连接参数
    client = AutoBlacklist(
        FIREWALL_IP,
        FIREWALL_PORT,
        FIREWALL_USER,
        FIREWALL_PASSWORD
    )
    # 执行单次检查
    result = client.single_threat_check(threshold=FIREWALL_THRESHOLD)
    # 处理结果
    try:
        if result:
            logger.info("\n=== 威胁检测报告 ===")
            logger.info("\n检测到的IP及出现次数：")
            for ip, count in result['detected_ips'].items():
                logger.info(f"\n  {ip}: {count}次")
            logger.info("\n已封禁的IP：")
            if len(result['blocked_ips']) == 0:
                logger.info("\n" + "无威胁IP达到阈值")
            else:
                logger.info("\n".join(f"  {ip}" for ip in result['blocked_ips']))
        else:
            logger.error("\n威胁检查失败")
            sys.exit(1)
    except Exception as exception:
        logger.error(f"处理结果时出错: {str(exception)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程序异常: {str(e)}")
        sys.exit(1)
