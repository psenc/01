# -*- coding: utf-8 -*-
# File   : source_code.py
# Author : senc
# Time   : 2023/2/26 19:12
# E-mail : psecnking@gmail.com
# Proposal : Life is short, you need Python.
from datetime import datetime
from os import system
from pathlib import Path
from time import sleep
from getpass4 import getpass
from threading import Thread
from telnetlib import Telnet

import paramiko
import re
import hashlib


def have(i: str):
    return i[:-1]


def no_have(i: str):
    return i


def have_port(p):
    return int(p)


def no_have_port(p):
    return 22


def ipt_params():
    username = input("输入用户名（所有设备均使用此用户名连接）:")
    password = getpass("输入密码（所有设备均使用此密码连接）:")
    port = input("输入SSH端口号（默认22可不输入）:")
    return username, password, port


class Ie:
    def __init__(self, ip, username, password, port=22):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.client = self.create_client()
        self.terminal = self.client.invoke_shell()

    def create_client(self):
        """
        生成一个SSH客户端
        :return:
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.ip, self.port, self.username, self.password)

        return client

    def send_command(self):
        """
        发送命令
        :return:配置写入完成
        """
        self.terminal.send("screen-length disable \r".encode("utf-8"))
        sleep(1)
        with open("command.txt", 'r', encoding='utf-8') as read_file:
            print("读取配置脚本.........\n")
            lines = read_file.readlines()
        for line in lines:
            line = (have if '\n' in line else no_have)(line)
            self.terminal.send((line + '\r').encode())
            sleep(2)
            print(self.terminal.recv(
                99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999).decode())
        sleep(2)
        return f"{self.ip}配置写入完成\n"

    def create_file(self):
        """
        创建文件用于存放导出的配置
        :return: 文件路径
        """
        current_path = Path.cwd()
        file_name = "collect_info/" + \
                    str(datetime.now()).replace("-", "_")[:10] + \
                    "_" + \
                    self.ip + \
                    ".txt"
        new_file_path = current_path / file_name
        Path.touch(new_file_path)
        print(f"创建 {file_name} 成功\n")
        return new_file_path

    def copy_config(self):
        """
        创建配置文件
        :return:拷贝成功
        """
        sftp = self.create_client().open_sftp()
        sftp.get(remotepath="startup.cfg", localpath=str(self.create_file()))
        print(f"正在从{self.ip}获取配置启动文件 startup.cfg\n")
        sleep(3)
        self.exit()
        return "拷贝完成\n"

    def create_specify_file(self, specify_file):
        """
        创建指定文件
        :return:文件路径
        """
        current_path = Path.cwd()
        file_name = "collect_info/" + \
                    str(datetime.now()).replace("-", "_")[:10] + \
                    "_" + \
                    self.ip + \
                    '_' + \
                    specify_file
        new_file_path = current_path / file_name
        Path.touch(new_file_path)
        print(f"创建 {file_name} 成功\n")
        return new_file_path

    def copy_specify_file(self, specify_file):
        sftp = self.create_client().open_sftp()
        sftp.get(remotepath=specify_file, localpath=str(self.create_specify_file(specify_file)))
        print(f"正在从{self.ip}获取配置启动文件 {specify_file}\n")
        sleep(3)
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
    username, password, port = ipt_params()
    port = (have_port if len(port) else no_have_port)(port)
    connect_failed_ip = []
    with open("device.ip.txt", 'r', encoding="utf-8") as read_file:
        iplist = read_file.readlines()
    for ip in iplist:
        ip = (have if '\n' in ip else no_have)(ip)
        print(f"正在连接{ip}")
        try:
            ie = Ie(ip, username, password, port)
            print(ie.send_command())
            ie.exit()
        except KeyboardInterrupt:
            print("用户Ctrl + C终止")
            break
        except paramiko.ssh_exception.AuthenticationException:  # type:ignore
            print("密钥错误")
            break
        except paramiko.ssh_exception.NoValidConnectionsError:
            print("端口号异常", port)
            break
        except TimeoutError:
            print(f"{ip}连接超时, 检查网络可达性\n")
            connect_failed_ip.append(ip)
            continue
        except paramiko.ssh_exception.SSHException:  # type:ignore
            print(f"{ip}可能未开启SSH或者SFTP, 确保服务后启动程序")
            continue
        except Exception as e:
            print("连接断开", e)
            continue
    print("本次不可达IP为")
    for ip in connect_failed_ip:
        print(f"\t{ip}")
    return '\n'


def download_config():
    """
    下载配置文件
    :return:None
    """
    username, password, port = ipt_params()
    port = (have_port if len(port) else no_have_port)(port)
    connect_failed_ip = []
    with open("device.ip.txt", 'r', encoding="utf-8") as read_file:
        lines = read_file.readlines()
    for line in lines:
        i = (have if '\n' in line else no_have)(line)
        print(f"正在连接{line}")
        try:
            ie = Ie(i, username, password, port)
            t = Thread(target=ie.copy_config)
            t.start()
            ie.exit()
        except KeyboardInterrupt:
            print("用户Ctrl + C终止")
            break
        except paramiko.ssh_exception.AuthenticationException:  # type:ignore
            print("密钥错误")
            break
        except paramiko.ssh_exception.NoValidConnectionsError:
            print("端口号异常", port)
            break
        except TimeoutError:
            print(f"{i}连接超时, 检查网络可达性")
            connect_failed_ip.append(i)
            continue
        except paramiko.ssh_exception.SSHException:  # type:ignore
            print(f"{i}可能未开启SSH或者SFTP, 确保服务后启动程序")
        except Exception as e:
            print("SFTP连接断开", e)
            continue
    sleep(3)
    print("本次不可达IP为")
    for ip in connect_failed_ip:
        print(f"\t{ip}")
    return "\n"


def download_specify_file():
    """
    下载设备中的指定文件
    :return: None
    """
    username, password, port = ipt_params()
    port = (have_port if len(port) else no_have_port)(port)
    specify_file = input("输入需要导出的文件名(写全):")
    connect_failed_ip = []
    with open("device.ip.txt", 'r', encoding="utf-8") as read_file:
        lines = read_file.readlines()
    for line in lines:
        i = (have if '\n' in line else no_have)(line)
        print(f"正在连接{line}")
        try:
            ie = Ie(i, username, password, port)
            t = Thread(target=ie.copy_specify_file, args=(specify_file,))
            t.start()
            ie.exit()
        except KeyboardInterrupt:
            print("用户Ctrl + C终止")
            break
        except paramiko.ssh_exception.AuthenticationException:  # type:ignore
            print("密钥错误")
            break
        except paramiko.ssh_exception.NoValidConnectionsError:
            print("端口号异常", port)
            break
        except TimeoutError:
            print(f"{i}连接超时, 检查网络可达性")
            connect_failed_ip.append(i)
            continue
        except paramiko.ssh_exception.SSHException:  # type:ignore
            print(f"{i}可能未开启SSH或者SFTP, 确保服务后启动程序")
        except Exception as e:
            print("SFTP连接断开", e)
            continue
    sleep(3)
    print("本次不可达IP为")
    for ip in connect_failed_ip:
        print(f"\t{ip}")
        return "\n"


def scan_port(ip, port):
    """
    端口扫描
    :return: None
    """
    scan = Telnet()
    try:
        scan.open(ip, port)
        print(f"\t{ip} 的 {port} 开放\n")
    except ConnectionRefusedError:
        pass
    except Exception:
        pass
    finally:
        scan.close()
    return '\n'


def run_scan():
    with open("device.ip.txt", 'r', encoding="utf-8") as read_file:
        lines = read_file.readlines()
    for line in lines:
        line = (have if '\n' in line else no_have)(line)
        print(f"正在扫描{line}\n")
        for port in range(1, 65535):
            s = Thread(target=scan_port, args=(line, port))
            s.start()
    sleep(1)


def about():
    author = "senc"
    email = "psencking@gmail.com"
    return f"作者:{author}\t邮箱:{email}"


def use():
    return "device.ip.txt存放所有IP, 确保IP地址正确, 一个IP独占一行, 没有多余的空格在IP地址前后方;\
    \ncommand.txt文件存放命令;\
    \n所有设备使用同一用户名、密钥连接, 确保用户名、密钥正确;\
    \n导出配置文件需要设备开启SFTP服务, 可通过导入配置的选项批量开启、关闭, 导出的配置文件名为年_月_日_x.x.x.x.txt;\
    \n端口扫描仅扫描device.ip.txt中的IP;\
    \n计算文件hash输入文件的路径即可。\
    \n\n导出其他文件示例:（无法导出大文件, 本示例以导出dis int brief命令回显为例）\
    \n\tcommand.txt书写dis int brief >> int_info.txt;     (意为将dis int brief回显的信息输出到int_info.txt文件中) \
    \n\tdevice.ip.txt书写需要导出文件的设备IP \
    \n\t将命令导入到设备中 \
    \n\t通过选项2将int_info.txt传到collect_info文件中"


def match_ip():
    """
    判断文件内的IP是否合规
    :return:None
    """
    match = []
    ip = []
    with open("./device.ip.txt", 'r', encoding="utf-8") as read_file:
        content = read_file.readlines()
    for line in content:
        if not (len(content)):
            print("device.ip.txt为空文件")
            break
        match += re.findall(
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[1-9]){1,3}\."
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[0-9]){1,3}\."
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[0-9]){1,3}\."
            r"(1[0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[1-9]){1,3}",
            line
        )
    if len(match) != len(content):
        print("device.ip.txt中存在不合规IP地址")
        for t in match:
            ip.append(t[0] + '.' + t[1] + '.' + t[2] + '.' + t[3])
        for item in content:
            item = (have if '\n' in item else no_have)(item)  # type:ignore
            if item in ip:
                continue
            elif item == '\n' or item == '':
                continue
            else:
                print(f"\t不合规地址:{item}")
    return '\n'


def file_hash():
    filepath = input("输入文件路径:")
    try:

        with open(filepath, 'rb') as read_file:
            content = read_file.read()
        md5 = hashlib.md5()
        md5.update(content)
    except OSError:
        return f"{filepath} 无法打开\n确保传入的路径是一个文件而不是目录以及文件的可操作权限"
    else:
        return f"{filepath} hash值为 {md5.hexdigest()}"


choices = {
    '1': ("1、导入配置\n", import_config),
    "2": ("2、下载启动配置文件\n", download_config),
    '3': ("3、导出指定文件\n", download_specify_file),
    '4': ("4、端口扫描\n", run_scan),
    '5': ("5、计算文件hash\n", file_hash),
    '6': ("6、关于\n", about),
    '7': ("7、查看使用帮助\n", use)
}


def file():
    """
    _summary_
        判断文件(夹)是否存在
            存在不进行操作；
            不存在则创建空文件
    :return: None
    """
    command_path = Path.cwd() / "command.txt"
    device_ip_path = Path.cwd() / "device.ip.txt"
    collect_info_path = Path.cwd() / "collect_info"
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


if __name__ == "__main__":
    # 检测是否存在文件
    f = Thread(target=file)
    f.start()
    try:
        # 检测IP是否合规
        match_ip()
        # 打印选项
        for key in choices:
            print(choices[key][0])
        # 输入选项
        ipt = input("输入选项:")
        # 判断文件内的IP是否合规
        match_ip()
        # 判断输入的选项是否合规
        if ipt not in choices.keys():
            print("输入点正常的东西")
            system("pause")
        # 合规运行
        else:
            print(choices[ipt][1]())
            system("pause")
    except FileNotFoundError:
        print("确保文件存在!!!")
        system("pause")
    except KeyboardInterrupt:
        print("用户Ctrl + C终止!!!")
        system("pause")
    except ValueError:
        print("端口号范围1-65535!!!")
        system("pause")
