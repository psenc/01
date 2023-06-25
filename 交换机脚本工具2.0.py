# -*- coding: utf-8 -*-
# File   : 交换机脚本工具2.0.py
# Author : senc
# Time   : 2023/6/20 18:55:32
# E-mail : psecnking@gmail.com
# Proposal : Life is short, you need Python.
from getpass4 import getpass
from time import sleep
from telnetlib import Telnet
from threading import Thread
from pathlib import Path
from datetime import datetime
from os import system

import hashlib
import re
import paramiko

command = "command.txt"  # 定义文件路径（同级目录下）
device_ip = "device.ip.txt"  # 定义文件路径（同级目录下）
collect_info = "collect_info"  # 定义文件夹路径（同级目录下）
connect_failed_ip = []  # 定义IP连接错误列表


def read_device_ip():
    """
读取设备IP
:return:
"""
    with open(device_ip, 'r', encoding="utf-8") as f:
        ip_list = f.readlines()
    return ip_list


def read_scripts():
    """
读取脚本内容
:return:
"""
    with open(command, 'r', encoding='utf-8') as read_script:
        print("读取配置脚本.........\n")
        command_list = read_script.readlines()
    return command_list


def file():
    """
_summary_
\t判断必要的文件(夹)是否存在
\t存在不进行操作；
\t不存在则创建空文件
:return: None
"""
    command_path = Path.cwd() / command
    device_ip_path = Path.cwd() / device_ip
    collect_info_path = Path.cwd() / collect_info
    if not (command_path.is_file()):
        print("\ncommand.txt文件不存在")
        Path.touch(command_path, mode=666)

    if not (device_ip_path.is_file()):
        print("\ndevice.ip.txt不存在")
        Path.touch(device_ip_path, mode=666)

    if not (collect_info_path.is_dir()):
        print("\ncollect_info文件夹不存在")
        Path.mkdir(collect_info_path, mode=666)

    return '\n'


def have_newline(i: str):
    """
判断是否存在换行
:return:
"""
    if '\n' == i[-1]:
        return i[:-1]
    else:
        return i


def have_port(p):
    """
判断是否输入端口号
:return:
"""
    if not p:
        return 22
    else:
        return int(p)


def ipt_params():
    """
接受用户的输入
:return:
"""
    username = input("输入用户名（所有设备均使用此用户名连接）:")  # type: ignore
    password = getpass("输入密码（所有设备均使用此密码连接）:")  # type: ignore
    port = input("输入SSH端口号（默认22可不输入）:")  # type: ignore
    return username, password, port


def create_specify_file(specify_file):
    """
创建指定文件
:return:文件路径
"""
    file_path = Path.cwd() / "collect_info" / str(datetime.now()).replace("-", "_")[:10] / '_' / specify_file
    Path.touch(file_path)
    print(f"创建 {str(file_path)} 成功\n")
    return str(file_path)


class Ie:
    def __init__(self, ip, username, password, port=22):  # type: ignore
        self.ip = ip  # 待连接设备IP
        self.port = port  # 设备SSH端口
        self.username = username  # 设备SSH用户名
        self.password = password  # 设备SSH密码
        self.client = self.create_client()  # SSH客户端对象
        self.terminal = self.client.invoke_shell()  # 实例化为伪终端

    def create_client(self):
        """
生成一个SSH客户端
:return:
"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.ip, self.port, self.username, self.password)

        return client

    def send_command(self, scripts):
        """
发送命令
:return:配置写入完成
"""
        self.terminal.send("screen-length disable \r".encode('utf-8'))
        for line in scripts:
            line = have_newline(line) + '\n\r'
            self.terminal.send(line.encode())
            sleep(1.5)
            print(self.terminal.recv(
                99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
            ).decode('utf-8'))

        return f"{self.ip}配置写入完成\n"

    def create_file(self):
        """
创建文件
:return: 文件路径
"""
        file_path = Path.cwd() / "collect_info" / str(datetime.now()).replace("-", "_")[:10] / '_' / self.ip / 'txt'
        Path.touch(file_path)
        print(f"创建 {str(file_path)} 成功\n")

        return str(file_path)

    def copy_config(self):
        """
创建sftp对象, 导出配置文件
:return:拷贝成功
"""
        sftp = self.create_client().open_sftp()
        sftp.get(remotepath="startup.cfg", localpath=self.create_file())
        print(f"正在从{self.ip}获取配置启动文件 startup.cfg\n")
        sleep(3)
        self.exit()

        return "拷贝完成\n"

    def copy_specify_file(self, specify_file):
        sftp = self.create_client().open_sftp()
        sftp.get(remotepath=specify_file, localpath=str(create_specify_file(specify_file)))
        print(f"正在从{self.ip}获取配置启动文件 {specify_file}\n")
        sleep(5)
        self.exit()

        return "拷贝完成\n"

    def exit(self):
        self.terminal.close()
        return None


def import_config():
    """
导入配置
:return:None
"""
    scripts = read_scripts()
    for ip in device_ip_list:
        have_newline(ip)
        print(f"正在连接{ip}")
        try:
            ie = Ie(ip, username, password, port)
            print(ie.send_command(scripts))
            ie.exit()
        except KeyboardInterrupt as e:
            print("用户Ctrl + C终止", e)
            pass
        except paramiko.ssh_exception.AuthenticationException as e:  # type:ignore
            print("密钥错误", e)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError as e:  # type: ignore
            print("端口号异常", '\n\n', e)
            pass
        except TimeoutError as e:
            print(f"{ip}连接超时\n", e)
            connect_failed_ip.append(ip)
            pass
        except paramiko.ssh_exception.SSHException as e:  # type:ignore
            print(f"{ip}可能未开启SSH或者SFTP, 确保服务后启动程序", e)
            connect_failed_ip.append(ip)
            pass
        except Exception as e:
            print(e)
            connect_failed_ip.append(ip)
            pass
        if connect_failed_ip:
            print("本次不可达IP为")
            for pre_ip in connect_failed_ip:
                print(f"\t{pre_ip}")
        return '\n'


def download_config():
    """
下载配置文件
:return:None
"""
    for ip in device_ip_list:
        have_newline(ip)
        print(f"正在连接{ip}")
        try:
            ie = Ie(ip, username, password, port)
            print(ie.copy_config())
            ie.exit()
        except KeyboardInterrupt as e:
            print("用户Ctrl + C终止", e)
            pass
        except paramiko.ssh_exception.AuthenticationException as e:  # type:ignore
            print("密钥错误", e)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError as e:  # type: ignore
            print("端口号异常", '\n\n', e)
            pass
        except TimeoutError as e:
            print(f"{ip}连接超时\n", e)
            connect_failed_ip.append(ip)
            pass
        except paramiko.ssh_exception.SSHException as e:  # type:ignore
            print(f"{ip}可能未开启SSH或者SFTP, 确保服务后启动程序", e)
            connect_failed_ip.append(ip)
            pass
        except Exception as e:
            print(e)
            connect_failed_ip.append(ip)
            pass
        if connect_failed_ip:
            print("本次不可达IP为")
            for pre_ip in connect_failed_ip:
                print(f"\t{pre_ip}")
        return '\n'


def download_specify_file():
    """
下载设备中的指定文件
:return: None
"""
    specify_file = input("输入需要导出的文件名(写全):")
    for ip in device_ip_list:
        have_newline(ip)
        print(f"正在连接{ip}")
        try:
            ie = Ie(ip, username, password, port)
            print(ie.copy_specify_file(specify_file))
            ie.exit()
        except KeyboardInterrupt as e:
            print("用户Ctrl + C终止", e)
            pass
        except paramiko.ssh_exception.AuthenticationException as e:  # type:ignore
            print("密钥错误", e)
            pass
        except paramiko.ssh_exception.NoValidConnectionsError as e:  # type: ignore
            print("端口号异常", '\n\n', e)
            pass
        except TimeoutError as e:
            print(f"{ip}连接超时\n", e)
            connect_failed_ip.append(ip)
            pass
        except paramiko.ssh_exception.SSHException as e:  # type:ignore
            print(f"{ip}可能未开启SSH或者SFTP, 确保服务后启动程序", e)
            connect_failed_ip.append(ip)
            pass
        except Exception as e:
            print(e)
            connect_failed_ip.append(ip)
            pass
        if connect_failed_ip:
            print("本次不可达IP为")
            for pre_ip in connect_failed_ip:
                print(f"\t{pre_ip}")
        return '\n'


def scan_port(ip, port: int):  # ignore
    """
端口扫描
:return: None
"""
    scan = Telnet()
    try:
        scan.open(ip, port)
        print(f"\t{ip} 的 {port} 开放\n")
    except Exception:
        pass
    finally:
        scan.close()
    return '\n'


def run_scan():
    for line in device_ip_list:
        line = have_newline(line)
        print(f"开始扫描{line}\n")
        for port in range(1, 65535):  # type: ignore
            s = Thread(target=scan_port, args=(line, port))
            s.start()
    sleep(1)


def use():
    return 'device.ip.txt存放所有IP, 确保IP地址正确, 一个IP独占一行, 没有多余的空格在IP地址前后方;\
\ncommand.txt文件存放命令;\
\n所有设备使用同一用户名、密钥连接, 确保用户名、密钥正确;\
\n导出配置文件需要设备开启SFTP服务, 可通过导入配置的选项批量开启、关闭, 导出的配置文件名为年_月_日_x.x.x.x.txt;\
\n端口扫描仅扫描device.ip.txt中的IP;\
\n计算文件hash输入文件的路径即可。\
\n\n导出其他文件示例:（无法导出大文件, 本示例以导出dis int brief命令回显为例）\
\n\tcommand.txt书写dis int brief >> int_info.txt;     (意为将dis int brief回显的信息输出到int_info.txt文件中) \
\n\tdevice.ip.txt书写需要导出文件的设备IP \
\n\t将命令导入到设备中 \
\n\t通过选项2将int_info.txt传到collect_info文件中'


def file_hash():
    filepath = input("输入文件路径:")
    try:

        with open(filepath, 'rb') as read_file:
            content = read_file.read()
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        sha256.update(content)
        md5.update(content)
    except OSError:
        return f"{filepath} 无法打开\n确保传入的路径是一个文件而不是目录以及文件的可操作权限"
    else:
        return f"{filepath}\nmd5 hash值为 {md5.hexdigest()}\nsha256 hash值为 {sha256.hexdigest()}"


def match_ip():
    """
判断文件内的IP是否合规
:return:None
"""
    match = []
    ip = []
    for line in device_ip_list:
        if not (len(device_ip_list)):
            print("device.ip.txt为空文件")
            break
        match += re.findall(
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[1-9]){1,3}\."
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[0-9]){1,3}\."
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[0-9]){1,3}\."
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[1-9]){1,3}",
            line
        )
    if len(match) != len(device_ip_list):
        print("device.ip.txt中存在不合规IP地址")
        for t in match:
            ip.append(t[0] + '.' + t[1] + '.' + t[2] + '.' + t[3])
        for item in device_ip_list:
            item = (have if '\n' in item else no_have)(item)  # type:ignore
            if item in ip:
                continue
            elif item == '\n' or item == '':
                continue
            else:
                print(f"\t不合规地址:{item}")
    return '\n'


def about():
    author = "senc"
    email = "psencking@gmail.com"
    return f"作者:{author}\t邮箱:{email}"


choices = {
    '1': ("1、导入配置\n", import_config),
    "2": ("2、下载启动配置文件\n", download_config),
    '3': ("3、导出指定文件\n", download_specify_file),
    '4': ("4、端口扫描\n", run_scan),
    '5': ("5、计算文件hash\n", file_hash),
    '6': ("6、关于\n", about),
    '7': ("7、查看使用帮助\n", use)
}


def run():
    if ipt in '123':
        print(choices[ipt][1]())
    else:
        print(choices[ipt][1]())


if __name__ == "__main__":
    # 检测是否存在文件
    file()
    device_ip_list = read_device_ip()
    # 检测IP是否合规
    match_ip()
    # 打印选项
    for key in choices:
        print(choices[key][0])
    # 输入选项
    ipt = input("输入选项:")
    # 判断输入的选项是否合规
    if ipt not in choices.keys():
        print("输入点正常的东西")
        system("pause")
    # 合规运行
    else:
        username, password, port = ipt_params()
        port = have_port(port)
        run()
        system("pause")
