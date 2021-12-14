# encoding='utf-8'
try:
    import netifaces as ni  # 用来获取所有网卡信息的,方面抓包的时候调用
except Exception as err:
    log.warning(
        'netifaces库导入失败!该库用来获取当前主机上的网卡信息,用于抓包调用.\nlinux系统执行 sudo pip3 install netifaces 进行安装.\nwin系统执行 pip install netifaces 进行安装.\n错误内容如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
try:
    import scapy, sys
# from scapy.all import *
except Exception as err:
    log.warning(
        'scapy库导入失败!该库用来进行发包和抓包.\nlinux系统执行 sudo pip3 install --pre scapy[complete]进行安装.\nwin系统执行 pip install --pre scapy[complete]进行安装.\n错误内容如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序


class packet():
    '''
    程序默认环境为CentOS7.5；支持Python3.6～3.7
    packet需要netifaces,scapy第三方库支持,没有相关配置执行如下命令即可:
    sudo pip3 install netifaces
    sudo pip3 install --pre scapy[complete]
    '''

    def __init__(self):
        '''
        初始化packet类:
        '''
        # self.__iface=''#保存网卡名词
        pass

    def net_card(self, name=''):
        '''
        获取所有网卡名称或网卡信息
        调用方式为:实例化类名.net_card('网卡名')
        返回信息为网卡名称的列表或网卡信息的列表
        如果name为空,则返回所有网卡列表;否则返回名称为'name值'的网卡连接信息
        '''
        if not name:
            try:
                self.__iface = ni.interfaces()
            except Exception as err:
                log.warning('获取网卡列表失败!错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                log.warning('网卡列表获取成功!')
                return self.__iface
        else:
            self.__iface = name
            try:
                self.__iface = ni.ifaddresses(self.__iface)
            except Exception as err:
                log.warning('获取网卡: ' + str(name) + ' 的信息失败!错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                log.warning('网卡: ' + str(name) + ' 的信息获取成功!')
                return self.__iface

    def get(self, iface=None, count=1, filter_=None, timeout=None):
        '''
        抓包
        调用方式为:实例化类名.get('网卡名','抓取的连接数量')
        iface为网卡名,默认为空
        count为抓取的连接数量,默认为1
        '''
        # count=0, store=True, offline=None,prn=None, lfilter=None,L2socket=None, timeout=None, opened_socket=None,stop_filter=None, iface=None, started_callback=None,session=None, session_args=[], session_kwargs={}
        if not iface:
            log.warning('请输入网卡名称!如果不清楚网卡名称,请先执行:实例化类名.net_card(),获取网卡名称.\n也可以通过执行:实例化类名.net_card(\'网卡名\')获取网卡具体信息.')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if not count:
            count = 0
        else:
            try:
                count = int(count)
            except Exception as err:
                log.warning('请输入有效的抓包数量!抓包数量为整数或整数文本.默认为1.')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if not timeout:
            timeout = None
        else:
            try:
                timeout = int(timeout)
            except Exception as err:
                log.warning('请输入有效的时间限制!时间限制为整数,单位为秒.默认不限制.')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            dpkt = sniff(iface=iface, filter=filter_, count=count, timeout=timeout)
        except Exception as err:
            log.warning('抓包失败!网卡: ' + str(iface) + ' 抓包失败!\n请检查是否以root权限执行本方法,或者参数配置是否有误.错误信息如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        else:
            return dpkt
