#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @FileName  :AutoBlacklist.py
# @Time      :2025-07-02
# @Author    :xgxdmx

import logging
import re
import sys
import time
import paramiko
import socket
from collections import defaultdict
from logging.handlers import TimedRotatingFileHandler

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
# 历史日志留存数量
HISTORY_LOG_COUNT = 10

# 配置日志系统
def get_logger(logger_name, log_file):
    # 创建日志处理器，每周一备份历史日志，超过指定数量后自动删除
    handler = TimedRotatingFileHandler(log_file, when='W0', interval=1, backupCount=HISTORY_LOG_COUNT, encoding='utf-8')
    # 创建日志格式器，指定日志信息输出格式
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # 将日志格式器添加到日志处理器中
    handler.setFormatter(formatter)
    # 创建日志器，并添加日志处理器
    logger = logging.getLogger(logger_name)
    # 设置日志级别
    logger.setLevel(logging.INFO)
    # 将日志器添加到日志处理器中
    logger.addHandler(handler)
    # 禁止日志事件传递到更到层级的logger，避免日志信息的重复记录
    logger.propagate = False
    return logger

# 创建全量日志器
main_logger = get_logger('AutoBlacklist', 'firewall_check.log')
# 添加控制台日志处理器
main_logger.addHandler(logging.StreamHandler())
# 创建IP黑名单日志器
blocked_ips_logger = get_logger('BlockedIPs', 'blocked_ips.log')

# 防火墙自动黑名单类
class AutoBlacklist:
    # 构造函数
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
            # 连接防火墙
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
            main_logger.info(f"成功连接到防火墙 {self.host}")
            return True
        # 处理连接失败
        except paramiko.AuthenticationException as auth_exception:
            main_logger.error(f"SSH认证失败: {str(auth_exception)[:200]}")
            return False
        except paramiko.SSHException as ssh_exception:
            main_logger.error(f"SSH异常: {str(ssh_exception)[:200]}")
            return False
        except socket.timeout as timeout_err:
            main_logger.error(f"连接超时: {str(timeout_err)}")
            return False
        except Exception as exception:
            main_logger.error(f"连接失败: {str(exception)[:200]}")
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
            main_logger.error(f"命令执行失败: {str(exception)[:200]}")
            return None

    # 执行配置命令
    def execute_config_command(self, command):
        try:
            self.send_command("system-view")
            output = self.send_command(command)
            self.send_command("return")
            return output
        except Exception as exception:
            main_logger.error(f"配置命令执行失败: {str(exception)}")
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
            main_logger.error(f"威胁检查失败: {str(exception)}")
            return None
        finally:
            self.disconnect()
    # 封禁指定IP
    def block_ip(self, ip):
        block_cmd = f"firewall blacklist item source-ip {ip} timeout {FIREWALL_BLOCK_TIME}"
        main_logger.info(block_cmd)
        self.execute_config_command(block_cmd)
        return True
    # 记录封禁的IP
    @staticmethod
    def log_blocked_ip(ip, count):
        # 创建黑名单IP日志器
        blocked_ips_logger.info(f"Blocked IP: {ip} (Count: {count})")
    # 断开连接
    def disconnect(self):
        if self.client:
            try:
                if self.shell:
                    self.shell.send("quit\n")
                    time.sleep(1)
                self.client.close()
                main_logger.info("SSH连接已关闭")
            except Exception as exception:
                main_logger.error(f"断开连接时出错: {str(exception)}")
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
            main_logger.info("\n=== 威胁检测报告 ===")
            main_logger.info("\n检测到的IP及出现次数：")
            for ip, count in result['detected_ips'].items():
                main_logger.info(f"\n  {ip}  {count}次")
            main_logger.info("\n已封禁的IP：")
            if len(result['blocked_ips']) == 0:
                main_logger.info("\n" + "无威胁IP达到阈值")
            else:
                main_logger.info("\n".join(f"  {ip}" for ip in result['blocked_ips']))
        else:
            main_logger.error("\n威胁检查失败")
            sys.exit(1)
    except Exception as exception:
        main_logger.error(f"处理结果时出错: {str(exception)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        main_logger.error(f"程序异常: {str(e)}")
        sys.exit(1)
