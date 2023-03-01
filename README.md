一、项目背景：
    想法源自于一次采集H3C交换机接口vlan信息，数量是真的多，所以就写了个程序。

二、需求：
    批量采集H3C交换机启动配置文件(flash:/startup.cfg)；
    批量导入配置，不过批量导入配置的设备的用户名密码和端口号都是一致的；
    通过paramiko实现。

三、使用：
    在同级目录下生成一个command.txt文件，存放了需要导入的命令；
    同级目录下生成一个device.ip.txt文件，存放了需要下载配置文件或者导入配置的设备IP地址；
    同级目录下生成一个collect_info的文件夹，用于存放导出的配置文件

目录树：
    |--source_code.py
    |--source_code.exe
    |--device.ip.txt
    |--command.txt
    |--collect_info
             |--年_月_日_x.x.x.x.cfg
外部库：
    通过pyinstaller封装了exe可执行文件。纯命令行使用。
    通过getpass4输入密码；
    当然，最核心的还是paramiko；
    还有其他一些需要用到的基本库，比如re、os、datetime之类的。

版本：
    源码使用python-3.10.8编写;
    paramiko: 2.12.0;
    getpass4: 0.0.14.0;
    pyinstaller: 5.7.0.
