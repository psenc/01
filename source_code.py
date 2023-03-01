from datetime import datetime
from os import system
from pathlib import Path
from time import sleep
from getpass4 import getpass
from threading import Thread

import paramiko
import re


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
        :return:
        """
        self.terminal.send("screen-length disable \r".encode("utf-8"))
        sleep(1)
        with open("command.txt", 'r', encoding='utf-8') as f:
            print("读取配置脚本.........\n")
            for line in f.readlines():
                self.terminal.send(line.encode())
                sleep(1)
                print(self.terminal.recv(
                    99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999).decode())
            return f"{self.ip}配置写入完成\n"

    def create_file(self):
        current_path = Path.cwd()
        file_name = "collect_info/" + str(datetime.now()).replace("-", "_")[:10] + "_" + self.ip + ".txt"
        new_file_path = current_path / file_name
        Path.touch(new_file_path)
        print("创建文件成功\n")
        return new_file_path

    def copy_config(self):

        sftp = self.create_client().open_sftp()
        sftp.get(remotepath="startup.cfg", localpath=str(self.create_file()))
        print(f"正在从{self.ip}获取配置启动文件 startup.cfg\n")
        sleep(3)
        self.exit()
        del self.client, sftp
        return "拷贝完成\n"

    def exit(self):
        self.terminal.close()


def have(i: str):
    return i[:-1]


def no_have(i: str):
    return i


def have_port(p):
    return int(p)


def no_have_port(p):
    return 22


def import_config():
    """
    导入配置
    :return:None
    """
    username = input("输入用户名（所有设备均使用此用户名连接）:")
    password = getpass("输入密码（所有设备均使用此密码连接）:")
    port = input("输入SSH端口号（默认22可不输入）:")
    port = (have_port if len(port) else no_have_port)(port)
    connect_failed_ip = []
    with open("device.ip.txt", 'r', encoding="utf-8") as f:
        for line in f.readlines():
            i = (have if '\n' in line else no_have)(line)
            print(f"正在连接{line}")
            try:
                ie = Ie(i, username, password, port)
                print(ie.send_command())
                ie.exit()
            except KeyboardInterrupt:
                print("用户Ctrl + C终止")
                break
            except paramiko.ssh_exception.AuthenticationException:
                print("密钥错误")
                break
            except TimeoutError:
                print(f"{i}连接超时, 检查网络可达性\n")
                connect_failed_ip.append(i)
                continue
            except paramiko.ssh_exception.SSHException:
                print(f"{i}可能未开启SSH或者SFTP, 确保服务后启动程序")
                continue
            except Exception:
                print("连接断开")
                continue
        print("本次不可达IP为")
        for ip in connect_failed_ip:
            print(f"\t{ip}")
        print()


def download_config():
    """
    下载配置文件
    :return:None
    """
    username = input("输入用户名（所有设备均使用此用户名连接）:")
    password = getpass("输入密码（所有设备均使用此密码连接）:")
    port = input("输入SSH端口号（默认22可不输入）:")
    port = (have_port if len(port) else no_have_port)(port)
    connect_failed_ip = []
    with open("device.ip.txt", 'r', encoding="utf-8") as f:
        for line in f.readlines():
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
            except paramiko.ssh_exception.AuthenticationException:
                print("密钥错误")
                break
            except TimeoutError:
                print(f"{i}连接超时, 检查网络可达性")
                connect_failed_ip.append(i)
                continue
            except paramiko.ssh_exception.SSHException:
                print(f"{i}可能未开启SSH或者SFTP, 确保服务后启动程序")
            except Exception:
                print("SFTP连接断开")
                continue
        print("本次不可达IP为")
        for ip in connect_failed_ip:
            print(f"\t{ip}")
        print()
    return None


def use():
    return "device.ip.txt存放所有IP, 确保IP地址正确, 一个IP独占一行, 没有多余的空格在IP地址前后方;\
    \ncommand.txt文件存放命令;\
    \n所有设备使用同一用户名、密钥连接, 确保用户名、密钥正确;\
    \n导出配置文件需要设备开启SFTP服务, 可通过导入配置的选项批量开启、关闭。"


def match_ip():
    """
    判断文件内的IP是否合规
    :return:None
    """
    match = []
    ip = []
    with open("./device.ip.txt", 'r', encoding="utf-8") as f:
        content = f.readlines()
        for line in content:
            if not(len(content)):
                print("device.ip.txt为空文件")
                break
            match += re.findall(r"([1][0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[1-9]){1,3}\.([1][0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[0-9]){1,3}\.([1][0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[0-9]){1,3}\.([1][0-9][0-9]|25[0-5]|2[0-4][0-9]|[1-9][0-9]|[1-9]){1,3}", line)
        if len(match) != len(content):
            print("device.ip.txt中存在不合规IP地址")
            for t in match:
                ip.append(t[0] + '.' + t[1] + '.' + t[2] + '.' + t[3])
            for item in content:
                item = (have if '\n' in line else no_have)(item)
                if item in ip:
                    continue
                elif item == '\n' or item == '':
                    continue
                else:
                    print(f"\t不合规地址:{item}")
    return None


choices = {
    '1': ("1、导入配置\n", import_config),
    "2": ("2、下载启动配置文件\n", download_config),
    '3': ("3、查看使用帮助\n", use)
}


def file():
    """
    判断文件(夹)是否存在
        存在不进行操作；
        不存在则创建空文件
    :return: None
    """
    command_path = Path.cwd()/"command.txt"
    device_ip_path = Path.cwd()/"device.ip.txt"
    collect_info_path = Path.cwd()/"collect_info"
    if not (command_path.is_file()):
        print("command.txt文件不存在")
        Path.touch(command_path, mode=666)

        if not (device_ip_path.is_file()):
            print("device.ip.txt不存在")
            Path.touch(device_ip_path)

            if not (collect_info_path.is_dir()):
                print("collect_info文件夹不存在")
                Path.mkdir(collect_info_path, mode=666)
                print("生成的文件需要存放在collect_info文件夹中")
    return None


if __name__ == "__main__":

    # 检测是否存在文件
    f = Thread(target=file)
    f.start()
    try:

        sleep(0.5)
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

    except KeyboardInterrupt:
        print("用户Ctrl + C终止")
        system("pause")
    except ValueError:
        print("端口号范围1-65535")
        system("pause")
