# encoding='utf-8'

# 以下参数配置仅与执行环境有关，与用例无关
version = '大版本_newDMS_1.0.11-p1'  # 版本信息
controlIp = '10.10.101.6'
'''
mode：代表的是执行ssh类型的链接还是其他的，例如：rabbitmq或其他类型的
需要在common同级目录建立Case_ssh文件夹，其中的ssh是mode变量的值，这个可以根据需要随意进行设置
为了便于理解与书写方便，建议ssh链接的定义为ssh；Rabbitmq链接的定义为rbm
同时，需要在common目录下建议caseselect_ssh.py文件，对Case_ssh目录中的单元测试例文件夹进行选择
其中的ssh是一一对应的'rbm', 'ssh'
'''
mode_list = ['rbm']  # 要测试的类型
strip = '[]\n'
qos_port = '8888'

# 发件设置
smtp_server = "smtphz.qiye.163.com"  # 发包服务器
sender_passwd = "Js1234"  # 发件箱密码
sender_addr = "baotest@jusontech.com"  # 发件箱
receiver_addr = ["wangqian@jusontech.com"]  # 收件人

# server的/usr/local/nginx/html路径下需要有get或者post需要的文件：test.php、juson.php、123.php（.php为post需要的）
http_proxy_port = 2287
# http_server_ip = '10.10.100.201'
http_server_ip = '192.168.50.26'
http_server_op_ip = '10.10.101.26'
http_redirect_ip = '10.10.101.22'
http_redirect_port = 8000
http_server_user = 'root'
http_server_pass = '3e2b6e75b403c492'
http_content = 'You got right!'
http_server_port = 80
http_server_port_file = 9999

udp_content = 'Thanks'

# appid
http_appid = 1
http_post_appid = 11
tcp_appid = 2
tcp_ssh_appid = 21
smtp_appid = 3
pop3_appid = 4
ftp_appid = 5
app_appid = 6
udp_appid=7

# ruleid
http_ruleid = 100
http_post_ruleid = 101
tcp_ruleid = 102
tcp_ssh_ruleid = 103
smtp_ruleid = 104
pop3_ruleid = 105
ftp_ruleid = 106
app_ruleid = 107

# mail相关参数设置
smtp_ip = '192.168.50.33'
pop3_ip = '192.168.50.33'
smtp_server_port = 25
pop3_server_port = 110
smtp_proxy_port = 8885
pop3_proxy_port = 8886
windows_sip = '10.10.100.136'  # 发送邮件的源ip，即运行环境的ip，即电脑的本机ip
mail_sender = 'autotest_send@jusontech.com'  # 发件人
mail_receivers = ['autotest_recv@jusontech.com']  # 收件人
mail_cc = ['autotest_send@jusontech.com', 'autotest_recv@jusontech.com']  # 抄送人
mail_bcc = ['autotest_send@jusontech.com', 'autotest_recv@jusontech.com']  # 暗送人
mail_user = "autotest_send@jusontech.com"  # 邮件登录地址
mail_pass = "1q2w3e"  # 授权码
pop3_email = "autotest_recv@jusontech.com"
pop3_pwd = "1q2w3e"  # 授权码

# ftp相关参数设置
ftp_proxy_port = 2121
ftp_ip = '10.10.101.193'
ftp_dport = 21
ftp_user = 'test'
ftp_pass = '1q2w3e'

# vxlan等封装报文的内层ip和port设置
vxlan_sip = '172.16.1.243'
vxlan_dip = '172.16.1.196'
vxlan_sp = 42982
vxlan_dp = 8889

# 定制应用（隔离）相关配置
iso_timeout = 10
ssh_dport = 22
ssh_proxy_port = 5555
app_proxy_port = 2220

# dns协议相关配置
dns_domain = 'www.test.com'
dns_port = 53
dns_proxy_port = 5353


# cipso相关参数设置
cipso_appid = 100


# 定义字典类型
DeviceObject = {}
# client端设置
DeviceObject['client', 'manageIp'] = "10.10.101.148"  # 设备的管理ip
DeviceObject['client', 'loginUser'] = "root"  # 登入的用户名
DeviceObject['client', 'loginPwd'] = "1q2w3e"  # 登入的密码
DeviceObject['client', 'operationIp'] = "192.168.30.148"  # 设备间通信的业务ip

# server端设置
DeviceObject['server', 'manageIp'] = "10.10.101.149"  # 设备的管理ip
DeviceObject['server', 'loginUser'] = "root"  # 登入的用户名
DeviceObject['server', 'loginPwd'] = "1q2w3e"  # 登入的密码
DeviceObject['server', 'operationIp'] = "192.168.50.149"  # 设备间通信的业务ip

# dut的设置
DeviceObject['gateway', 'manageIp'] = "10.10.101.47"  # 设备的管理ip，若管理ip无法直连，则添加路由使其通信
DeviceObject['gateway', 'loginUser'] = "root"  # 登入的用户名
DeviceObject['gateway', 'loginPwd'] = "1q2w3e"  # 登入的密码
DeviceObject['gateway', 'operationIpClient'] = "192.168.30.47"  # 设备间通信的业务ip（client）
DeviceObject['gateway', 'operationIpServer'] = "192.168.50.47"  # 设备间通信的业务ip（server）
DeviceObject['gateway', 'InternetIpServer'] = "10.10.101.47"  # 设备间通信的业务ip（server）
DeviceObject['gateway', 'vlanIp'] = "11.11.11.11"  # vlan聚合用到的ip地址
DeviceObject['gateway', 'vlanIfname2'] = "enp59s0f12"  # vlan聚合的ip对应的另一个接口名（针对bond）
DeviceObject['gateway', 'vlanIfname'] = "enp59s0f13"  # vlan聚合的ip对应的接口名
DeviceObject['gateway', 'vlanIfnumber'] = 4  # vlan聚合的ip对应的接口序列号（从0开始排序）
DeviceObject['gateway', 'other1Ifname'] = "enp59s0f00"  # vlan聚合的所在卡对应的其他接口名
DeviceObject['gateway', 'other2Ifname'] = "enp59s0f01"  # vlan聚合的所在卡对应的其他接口名
DeviceObject['gateway', 'card0'] = "CS807304LV200A1N028"  # cardid为0的网卡序列号
DeviceObject['gateway', 'card1'] = "CS807304LV200A1N062"  # cardid为1的网卡序列号
DeviceObject['gateway', 'vlanCard'] = "CS807304LV200A1N042"  # vlan聚合的ip所在的网卡序列号
DeviceObject['gateway', 'vlanCardid'] = 0  # vlan聚合的ip所在的网卡是卡0还是卡1
DeviceObject['gateway', 'manageCardId'] = "1"  # 管理ip所在的卡id

# vlan聚合主机A设置
DeviceObject['vlanA', 'manageIp'] = "10.10.100.1"  # 设备的管理ip
DeviceObject['vlanA', 'loginUser'] = "root"  # 登入的用户名
DeviceObject['vlanA', 'loginPwd'] = "3e2b6e75b403c492"  # 登入的密码
DeviceObject['vlanA', 'operationIp'] = "11.11.11.100"  # 设备间通信的业务ip
DeviceObject['vlanA', 'operationMac'] = "ac:1f:6b:e1:04:f7"  # 业务ip对应的mac地址
DeviceObject['vlanA', 'vlan'] = 63  # 设备间通信的vlan

# vlan聚合主机B设置
DeviceObject['vlanB', 'manageIp'] = "10.10.88.53"  # 设备的管理ip
DeviceObject['vlanB', 'loginUser'] = "root"  # 登入的用户名
DeviceObject['vlanB', 'loginPwd'] = "1q2w3e"  # 登入的密码
DeviceObject['vlanB', 'operationIp'] = "11.11.11.53"  # 设备间通信的业务ip
DeviceObject['vlanB', 'operationMac'] = "ac:1f:6b:3a:fe:ba"  # 业务ip对应的mac地址
DeviceObject['vlanB', 'vlan'] = 64  # 设备间通信的vlan

vlanAIp = DeviceObject['vlanA', 'manageIp']
vlanAUser = DeviceObject['vlanA', 'loginUser']
vlanAPwd = DeviceObject['vlanA', 'loginPwd']
vlanAOpeIp = DeviceObject['vlanA', 'operationIp']
vlanAOpeMac = DeviceObject['vlanA', 'operationMac']
vlanA = DeviceObject['vlanA', 'vlan']

vlanBIp = DeviceObject['vlanB', 'manageIp']
vlanBUser = DeviceObject['vlanB', 'loginUser']
vlanBPwd = DeviceObject['vlanB', 'loginPwd']
vlanBOpeIp = DeviceObject['vlanB', 'operationIp']
vlanBOpeMac = DeviceObject['vlanB', 'operationMac']
vlanB = DeviceObject['vlanB', 'vlan']

clientIp = DeviceObject['client', 'manageIp']
clientUser = DeviceObject['client', 'loginUser']
clientPwd = DeviceObject['client', 'loginPwd']
clientOpeIp = DeviceObject['client', 'operationIp']

serverIp = DeviceObject['server', 'manageIp']
serverUser = DeviceObject['server', 'loginUser']
serverPwd = DeviceObject['server', 'loginPwd']
serverOpeIp = DeviceObject['server', 'operationIp']

gwManageIp = DeviceObject['gateway', 'manageIp']
gwUser = DeviceObject['gateway', 'loginUser']
gwPwd = DeviceObject['gateway', 'loginPwd']
gwClientIp = DeviceObject['gateway', 'operationIpClient']
gwServerIp = DeviceObject['gateway', 'operationIpServer']
gwInternetIp = DeviceObject['gateway', 'InternetIpServer']
gwVlanIp = DeviceObject['gateway', 'vlanIp']
gwVlanIfname = DeviceObject['gateway', 'vlanIfname']
gwVlanIfname2 = DeviceObject['gateway', 'vlanIfname2']
gwVlanIfnumber = DeviceObject['gateway', 'vlanIfnumber']
gwOther1Ifname = DeviceObject['gateway', 'other1Ifname']
gwOther2Ifname = DeviceObject['gateway', 'other2Ifname']
gwCard0 = DeviceObject['gateway', 'card0']
gwCard1 = DeviceObject['gateway', 'card1']
gwManageCardId = DeviceObject['gateway', 'manageCardId']
gwVlanCard = DeviceObject['gateway', 'vlanCard']
gwVlanCardid = DeviceObject['gateway', 'vlanCardid']

# 定义隔离组网
BG8010 = {}
# 隔离client的设置
BG8010['client', 'manageIp'] = "10.10.101.180"  # 隔离测试客户端管理IP
BG8010['client', 'loginUser'] = "root"  # 登录账户
BG8010["client", "loginPwd"] = "3e2b6e75b403c492"  # 登录密码
BG8010["client", "operationIp"] = "192.168.30.180"  # 设备间通信用的业务IP

# 隔离server端的设置,101.26上配置好了dns
BG8010['server', 'manageIp'] = "10.10.101.26"  # 隔离测试服务器端管理IP
BG8010['server', 'loginUser'] = "root"  # 登录账户
BG8010["server", "loginPwd"] = "3e2b6e75b403c492"  # 登录密码
BG8010["server", "operationIp"] = "192.168.50.26"  # 设备间通信用的业务IP

# 隔离设备端的设置
BG8010['front_dut', 'manageIp'] = "10.10.101.111"  # 隔离测试前置机管理IP
BG8010['front_dut', 'loginUser'] = "root"  # 登录账户
BG8010["front_dut", "loginPwd"] = "1q2w3e"  # 登录密码
BG8010["front_dut", "operationIp"] = "192.168.30.111"  # 设备间通信用的业务IP
BG8010["front_dut", "operationIfname"] = "enp60s0f00"  # 设备接口名
BG8010["front_dut", "operationBond"] = "bond1"  # 前置机bond口
BG8010["front_dut", "operationBondIp"] = "192.168.80.234"  # 前置机bond ip
BG8010["front_dut", "operationNum"] = "2"  # 该业务ip所在的接口号，从1开始排序
BG8010["front_dut", "domain"] = "hf.f1203.g01.cs_17.iso111"  # 前置机domain
BG8010["front_dut", "cardid"] = "CS807304LV200A1N038"  # 前置机安全卡code

BG8010['back_dut', 'manageIp'] = "10.10.101.112"  # 隔离测试后置机管理IP
BG8010['back_dut', 'loginUser'] = "root"  # 登录账户
BG8010["back_dut", "loginPwd"] = "1q2w3e"  # 登录密码
BG8010["back_dut", "operationIpInside"] = "192.168.50.112"  # 设备间通信用的内网业务IP
BG8010["back_dut", "operationIfnameInside"] = "enp60s0f00"  # 内网业务ip对应的接口名
BG8010["back_dut", "operationIpOutside"] = "10.10.101.112"  # 设备间通信用的外网业务IP
BG8010["back_dut", "operationIfnameOutside"] = "enp60s0f01"  # 外网业务ip对应的接口名
BG8010["back_dut", "domain"] = "hf.f1203.g01.cs_17.iso112"  # 后置机domain
BG8010["back_dut", "cardid"] = "CS807304LV200A1N033"  # 后置机安全卡code

# 隔离client的设置
BG8010ClientIp = BG8010['client', 'manageIp']
BG8010ClientUser = BG8010['client', 'loginUser']
BG8010ClientPwd = BG8010["client", "loginPwd"]
BG8010ClientOpeIp = BG8010["client", "operationIp"]

# 隔离server端的设置
BG8010ServerIp = BG8010['server', 'manageIp']
BG8010ServerUser = BG8010['server', 'loginUser']
BG8010ServerPwd = BG8010["server", "loginPwd"]
BG8010ServerOpeIp = BG8010["server", "operationIp"]

# 隔离设备端的设置
BG8010FrontIp = BG8010['front_dut', 'manageIp']
BG8010FrontUser = BG8010['front_dut', 'loginUser']
BG8010FrontPwd = BG8010["front_dut", "loginPwd"]
BG8010FrontOpeIp = BG8010["front_dut", "operationIp"]
BG8010FrontOpeIfname = BG8010["front_dut", "operationIfname"]
BG8010FrontOpeNum = BG8010["front_dut", "operationNum"]
BG8010FrontDomain = BG8010["front_dut", "domain"]
BG8010FrontCardid = BG8010["front_dut", "cardid"]
BG8010FrontBond = BG8010["front_dut", "operationBond"]
BG8010FrontBondIp = BG8010["front_dut", "operationBondIp"]

BG8010BackIp = BG8010['back_dut', 'manageIp']
BG8010BackUser = BG8010['back_dut', 'loginUser']
BG8010BackPwd = BG8010["back_dut", "loginPwd"]
BG8010BackOpeIpInside = BG8010["back_dut", "operationIpInside"]
BG8010BackOpeIfnameInside = BG8010["back_dut", "operationIfnameInside"]
BG8010BackOpeIpOutside = BG8010["back_dut", "operationIpOutside"]
BG8010BackOpeIfnameOutside = BG8010["back_dut", "operationIfnameOutside"]
BG8010BackDomain = BG8010["back_dut", "domain"]
BG8010BackCardid = BG8010["back_dut", "cardid"]

# rabbitmq相关的设置
DeviceObject['rabbitmq', 'manageIp'] = "10.10.101.233"  # rabbitmq server所在服务器地址
DeviceObject['rabbitmq', 'loginUser'] = "root"  # 登入的用户名
DeviceObject['rabbitmq', 'loginPwd'] = "1q2w3e"  # 登入的密码
DeviceObject['rabbitmq', 'rbmUser'] = "admin"  # rabbitmq登录用户名
DeviceObject['rabbitmq', 'rbmPwd'] = "654321"  # rabbitmq登录密码
DeviceObject['rabbitmq', 'DeviceDomain'] = 'hf.f1203.g01.cs_17.wg47'  # 设备domain代码
DeviceObject['rabbitmq', 'exchanges'] = 'ManageExchange'  # 交换机名称

# 报文相关的设置(网口与执行环境有关)
DeviceObject['packet', 'sendIface'] = "ens10"  # 报文发送时的出接口
DeviceObject['packet', 'gwIface'] = "enp59s0f00"  # 报文发送时的出接口
DeviceObject['packet', 'readIface'] = "ens10"  # 抓取报文时的接口

# 文件路径设置
ftp_upremotePath = '/home/ftp/ftp_auto/'  # ftp上传的ftp服务器路径
ftp_uplocalPath = 'C:\\Users\\admin\\Desktop\\work\\'  # ftp上传的本地路径
ftp_uploadDirPath = 'C:\\Users\\admin\\Desktop\\work\\uploadDir\\'  # ftp上传文件夹的本地路径
ftp_downremotePath = '/home/ftp/ftp_auto/'  # ftp下载的ftp服务器路径
ftp_downlocalPath = 'C:\\Users\\admin\\Desktop\\work\\downfile\\'  # ftp下载的本地路径
ftp_delePath = '/home/ftp/ftp_auto/ftp_del'  # ftp删除的路径
mail_attach = 'C:\\Users\\admin\\Desktop\\work\\'  # 邮件发送的附件路径
http_downlocalPath = 'C:\\Users\\admin\\Desktop\\work\\httpdown\\'  # ftp下载的本地路径
http_uplocalPath = 'C:\\Users\\admin\\Desktop\\work\\'

rbmIp = DeviceObject['rabbitmq', 'manageIp']
rbmUser = DeviceObject['rabbitmq', 'loginUser']
rbmPwd = DeviceObject['rabbitmq', 'loginPwd']
rbmWebUser = DeviceObject['rabbitmq', 'rbmUser']
rbmWebPwd = DeviceObject['rabbitmq', 'rbmPwd']
rbmDomain = DeviceObject['rabbitmq', 'DeviceDomain']
rbmExc = DeviceObject['rabbitmq', 'exchanges']

pcapSendIface = DeviceObject['packet', 'sendIface']
pcapGwIface = DeviceObject['packet', 'gwIface']
pcapReadIface = DeviceObject['packet', 'readIface']

http_proxy_ip = gwClientIp + ':' + str(http_proxy_port)
http_proxy_url = 'http://' + http_proxy_ip

ftp_proxy_ip = gwClientIp + ':' + str(ftp_proxy_port)
smtp_proxy_ip = gwClientIp + ':' + str(smtp_proxy_port)
pop3_proxy_ip = gwClientIp + ':' + str(pop3_proxy_port)
