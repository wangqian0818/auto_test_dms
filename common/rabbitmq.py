'''
修订人：
修订时间：
修订内容：
1、
2、
3、
'''
# encoding='utf-8'
import logging

log = logging.getLogger(__name__)
try:
    import os, sys, json, copy, time, threading, pika, ssl
except Exception as err:
    log.warning('库文件导入失败!请检查需要导入的库文件是否已正确安装.\n错误信息如下:')
    log.warning(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

current_path = os.path.abspath(__file__)
father_path = os.path.abspath(os.path.dirname(current_path) + os.path.sep + ".")

ssl_opts = {
    "ca_certificate": str(father_path + '\\cacert.pem').replace('\\', '/'),
    "cert_reqs": ssl.CERT_REQUIRED,
    "ssl_version": ssl.PROTOCOL_TLSv1_2,
    "agentjsac.cert": str(father_path + '\\agentjsac.cert.pem').replace('\\', '/'),
    "agentjsac.key": str(father_path + '\\agentjsac.key.pem').replace('\\', '/')
}


class rabbitmq():
    '''
    程序默认环境为CentOS7.5；支持Python3.6～3.7
    rabbitmq需要第三方库pika,没有相关库的,执行如下命令即可:
    sudo pip3 install pika
    '''

    def __init__(self, host='', name='', passwd='', base_path='', port=5672):
        '''
        初始化rabbitmq类:host为rabbitmq服务器地址;name为rabbitmq服务器登陆帐号;passwd为rabbitmq登陆密码;queue为传输管道;port为rabbit服务器侦听端口,默认为5672
        类的实例化方法为:实例化类名.rabbitmq('rabbitmq服务器地址','rabbitmq侦听端口:可以留空','登陆帐号:不可以留空','登陆密码:不可以留空')
        host:rabbitmq主机地址
        name:rabbitmq登陆帐号
        passwd:rabbitmq登陆密码
        base_path:case单元测试例的文件夹绝对地址
        port:rabbitmq的端口,默认为:5672!!!不是15672!!!
        '''
        if (not name) or (not passwd) or (not host) or (not base_path):
            log.warning('rabbitmq服务器地址,帐号和密码以及单元测试例的绝对目录地址都不可以为空!')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        else:
            self.__host = str(host)  # Rabbitmq服务器地址
            self.__name = str(name)  # Rabbitmq用户名
            self.__passwd = str(passwd)  # Rabbitmq用户密码
            self.__rabbitmq_path = base_path
            # 数据流量周期上报队列
            self.__flow_exchange_type = 'topic'
            self.__flow_durable = True
            # 控制指令交互队列
            self.__manage_exchange_type = 'direct'
            self.__manage_durable = True
            # 全局队列
            self.__global_exchange_type = 'topic'
            self.__global_durable = True
            if not port:
                port = 5671
            self.__port = int(port)  # Rabbitmq端口号
            self.__thread_time = {}  # 关闭当前类时,定义为关闭时的时间戳
            self.__domain = []  # 保存queue-domain值
            '''
            如果python的执行目录不是当前目录,递归查找的时候,容易出现异常错误,避免出现异常,写死查找路径
            '''
            base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
            base_path = base_path.replace('\\', '/')
            self.__base_path = base_path
            sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件
            try:  # 导入版本配置等文件
                import baseinfo as info
            except Exception as err:
                log.warning('版本配置文件导入失败!请检查: ' + base_path + '/common/baseinfo.py 文件是否存在.\n错误信息如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误
                try:
                    self.__version = info.version  # 获取版本号
                except Exception as err:
                    log.warning('版本号获取失败!请检查是否设置了版本号.错误信息如下:')
                    log.warning(err)
                    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            base_path = os.path.dirname(self.__base_path)  # 获取当前项目的上级文件夹
            self.__logs_path = base_path
            # 验证并创建log保存目录
            if not os.path.exists(base_path + '/Logs/' + str(self.__version)):  # 如果保存当前版本的logs目录不存在,就创建
                try:
                    os.makedirs(base_path + '/Logs/' + str(self.__version))
                except Exception as err:
                    log.warning('保存当前版本的Logs目录创建失败!请检查文件夹是否有操作权限.\n错误信息如下:')
                    log.warning(err)
                    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            try:
                if port == 5671:
                    context = ssl.create_default_context(cafile=ssl_opts["ca_certificate"])
                    context = ssl._create_unverified_context()
                    context.load_cert_chain(ssl_opts["agentjsac.cert"], ssl_opts["agentjsac.key"])
                    ssl_options = pika.SSLOptions(context, self.__host)
                    self.__rabbitmq = pika.ConnectionParameters(self.__host, self.__port, '/',
                                                                pika.PlainCredentials(self.__name, self.__passwd),
                                                                ssl_options=ssl_options)  # 定义Rabbitmq连接
                    log.warning(self.__rabbitmq)
                elif port == 5672:
                    self.__rabbitmq = pika.ConnectionParameters(self.__host, self.__port, '/',
                                                                pika.PlainCredentials(self.__name, self.__passwd)
                                                                )  # 定义Rabbitmq连接
                log.warning(self.__rabbitmq)
            except Exception as err:
                log.warning(
                    'Rabbitmq初始化失败!: ' + str(self.__host) + ':' + str(self.__port) + ' \n请检查相关参数的顺序和数据是否有误.错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                # ssh服务器连接状态
                self.__state = 0
                log.warning('Rabbitmq初始化完成: ' + str(self.__host) + ':' + str(self.__port))
            '''
            try:
                log.warning('self.base_path: '+self.__rabbitmq_path+'/message.py')
                #获取当前项目文件夹
                if not os.path.exists(self.__rabbitmq_path+'/message.py'):
                    log.warning('请输入正确的单元测试例目录,并且在单元测试例目录下要存在message.py文件!\nmessage.py源文件在: '+str(self.__base_path)+' 目录下.')
                    sys.exit(0)#避免程序继续运行造成的异常崩溃,友好退出程序
                with open(self.__rabbitmq_path+'/message.py','r',encoding='utf-8') as f:
                    self.__msg=json.loads(f.read())
            except Exception as err:
                log.warning('获取预设信息失败!错误信息如下:')
                log.warning(err)
                sys.exit(0)#避免程序继续运行造成的异常崩溃,友好退出程序
            '''

    #
    # def connect(self):
    #     '''
    #     连接Rabbitmq服务器
    #     调用方式为:实例化类名.connect()
    #     '''
    #     if self.__state:
    #         log.warning('Rabbitmq服务器: ' + str(self.__host) + ':' + str(
    #             self.__port) + ' 已连接!如果想建立新的连接,请执行:实例化类名.close()关闭以前的连接后,重新执行本方法.')
    #         sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
    #     else:
    #         try:
    #             # 建立连接
    #             self.__s_rabbitmq = pika.BlockingConnection(self.__rabbitmq)  # 连接发送信息管道
    #             # 建立通道
    #             self.__s_channel: pika.adapters.blocking_connection.BlockingChannel = self.__s_rabbitmq.channel()
    #         except Exception as err:
    #             log.warning('Rabbitmq连接服务器: ' + str(self.__host) + ':' + str(
    #                 self.__port) + ' 失败!请检查相关参数的顺序和数据是否有误.\n服务器和本地网络异常也会导致连接失败.错误内容如下:')
    #             log.warning(err)
    #             sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
    #         else:
    #             self.__state = 1
    #             log.warning('Rabbitmq服务器连接: ' + str(self.__host) + ':' + str(self.__port) + ' 成功.')

    def close(self):
        '''
        关闭Rabbitmq服务器连接
        调用方式为:实例化类名.close()
        '''
        if self.__state:
            try:
                self.__s_rabbitmq.close()
            except Exception as err:
                log.warning('Rabbitmq连接: ' + str(self.__host) + ':' + str(self.__port) + ' 关闭失败!请检查相关配置.错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                self.__state = 0

                log.warning('Rabbitmq连接: ' + str(self.__host) + ':' + str(self.__port) + ' 已断开.')
        else:
            log.warning('Rabbitmq连接: ' + str(self.__host) + ':' + str(self.__port) + ' 在此之前未成功连接或在此之前已断开连接.')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

    def reset(self, **exc):
        '''
        设置交换机类型和durable的值
        调用方式为:实例化类名.reset('交换机基础类型设置字典')
        一般只有在调用send()发送信息失败时才调用
        传入参数格式为:
        {'name':'flow','value':'topic','able':'ture'}或
        {'name':'manage','value':'topic','able':'ture'}或
        {'name':'global','value':'topic','able':'ture'}
        只有在调用send失败时,根据错误信息进行修改
        flow,manage,global分别对应:流量周期上报队列,控制指令交互队列,全局队列
        value:根据错误信息提示输入不同的类型
        able:根据错误信息提示,输入ture或false
        '''
        msg = '''
        reset方法传入参数格式为:
        {'name':'flow','value':'topic','able':'ture'}或
        {'name':'manage','value':'topic','able':'ture'}或
        {'name':'global','value':'topic','able':'ture'}
        只有在调用send失败时,根据错误信息进行修改
        flow,manage,global分别对应:流量周期上报队列,控制指令交互队列,全局队列
        value:根据错误信息提示输入不同的类型
        able:根据错误信息提示,输入ture或false'''
        if not isinstance(exc, dict):  # 如果不是字典类型,自动停止
            log.warning(msg)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        key = exc.keys()  # 返回所有的建
        if ('name' not in key) and (('value' not in key) or ('able' not in key)):
            log.warning(msg)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if exc['name'] != 'flow' and exc['name'] != 'manage' and exc['name'] != 'global':
            log.warning(msg)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if exc['name'] == 'flow':
            if 'value' in key:
                self.__flow_exchange_type = exc['value']
            if 'able' in key:
                self.__flow_durable = exc['able']
        if exc['name'] == 'manage':
            if 'value' in key:
                self.__manage_exchange_type = exc['value']
            if 'able' in key:
                self.__manage_durable = exc['able']
        if exc['name'] == 'global':
            if 'value' in key:
                self.__global_exchange_type = exc['value']
            if 'able' in key:
                self.__global_durable = exc['able']

    def send(self, exc='ManageExchange', method='', domain='', path=''):
        '''
        通过交换机向rabbitmq发送信息
        调用方式为:实例化类名.send('交换机名称','后台处理methodname','agent的域名','发送的信息:以字典的形式,否则会报错!')
        exc:交换机名称,不可为空
        method:后台处理的methodname,可为空
        domain:agent的域名
        **msg:要向Rabbitmq发送的信息,以字典的形式存储
        如果提示:exchange_type或durable错误,请先执行reset方法后,再调用本方法.具体操作方式可查看reset的帮助文档.
        '''
        if not exc:
            log.warning('请输入交换机名称!')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if not domain:
            log.warning('请输入anget主机名domain!\nanegt主机名由后台服务提供.')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if exc == 'ManageExchange':
            exc_type = self.__manage_exchange_type
            able = self.__manage_durable
        elif exc == 'GlobalExchange':
            exc_type = self.__global_exchange_type
            able = self.__global_durable
        else:
            exc_type = self.__flow_exchange_type
            able = self.__flow_durable
        # try:
        # 	log.warning('-----------'+path+'--------------------')
        # 	# path = path.replace('\\', '/')
        # 	# sys.path.insert(0, path)
        # 	if not os.path.exists(path+'/message.py'):
        # 		log.warning('请输入正确的单元测试例目录,并且在单元测试例目录下要存在message.py文件!')
        # 		sys.exit(0)
        # 	# path = path.split('/')[-1]
        # 	# # with open(path+'/message.py','r',encoding='utf-8') as f:
        # 	# 	# self.__msg=json.loads(f.read())
        # 	# self.__msg = message.data
        # 	# del sys.path[0]
        # except Exception as err:
        # 	log.warning('获取rmb接口参数失败，错误信息如下：')
        # 	log.warning(err)
        # 	sys.exit(0)

        if method:
            # if method not in self.__msg.keys():
            msg_0 = method
        # log.warning('methodname输入错误!请检查后重新输入.\n如果添加了新的methodname,请在: '+path+'/message.py 文件中修改相应的配置.')
        # sys.exit(0)#避免程序继续运行造成的异常崩溃,友好退出程序
        # else:
        # 	msg_0 = copy.deepcopy(self.__msg[method])#获取要发送的信息
        else:
            log.warning('请输入有效的Methodname!')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            try:
                # 建立连接
                self.__s_rabbitmq = pika.BlockingConnection(self.__rabbitmq)  # 连接发送信息管道
                # 建立通道
                self.__s_channel: pika.adapters.blocking_connection.BlockingChannel = self.__s_rabbitmq.channel()
                # 连接交换机
                self.__s_channel.exchange_declare(exchange=exc, exchange_type=exc_type, durable=able)
            except Exception as err:
                log.warning('Rabbitmq连接服务器: ' + str(self.__host) + ':' + str(
                    self.__port) + ' 失败!请检查相关参数的顺序和数据是否有误.\n服务器和本地网络异常也会导致连接失败.错误内容如下:')
                log.warning(err)
                sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
            else:
                self.__state = 1
                log.warning('Rabbitmq服务器连接: ' + str(self.__host) + ':' + str(self.__port) + ' 成功.')

        except Exception as err:
            log.warning('exchange=%s,exchange_type=%s,durable=%s' % {exc, exc_type, able})
            log.warning('send:交换机连接失败!可能是网络原因或配置信息错误.错误信息如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:  # 需要后台提供queue,然后对exchange绑定queue,将消息传输到对应的queue
            self.__s_channel.queue_bind(exchange=exc, queue=domain + '.down')
        except Exception as err:
            log.warning('queue绑定失败!可能是网络原因或配置信息错误.错误信息如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            msg_0['MessageTime'] = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            msg_0 = json.dumps(msg_0)
            self.__s_channel.basic_publish(exchange=exc, routing_key=domain + '.down', body=msg_0)  # 向交换机exc发送数据msg
        except Exception as err:
            log.warning('向Rabbitmq发送信息失败!错误信息如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        else:
            # log.warning('向Rabbitmq发送信息成功!')
            self.__thread_time[domain] = time.time()  # 将当前domian最后一次发送成功信息的时间保存
            with open(self.__logs_path + '/Logs/' + str(self.__version) + '/rabbitmq.logs', 'a', encoding='utf-8') as f:
                f.write('Domain: ' + str(domain) + ' Send: ' + str(msg_0) + '\n\n')
            if domain not in self.__domain:  # 如果接收线程未开启
                try:
                    self.__domain.append(domain)
                    rev = threading.Thread(target=self.__receive, args=(exc, self.__domain[-1]), name=str(domain))
                    rev.start()
                except Exception as err:
                    del self.__domain[-1]
                    log.warning('Domain值为: ' + str(self.__domain[-1]) + '的Rabbitmq信息接收线程获取失败!\n错误信息如下:')
                    log.warning(err)
                    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                else:
                    log.warning('Domain值为: ' + str(self.__domain[-1]) + '的Rabbitmq信息接收线程已开启!')

    def __receive(self, exc='', domain=''):
        '''
        receive线程函数,内部调用,不可外部访问
        '''
        if not exc:
            log.warning('请输入交换机名称!')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if not domain:
            log.warning('请输入anget主机名domain!\nanegt主机名由后台服务提供.')
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        if exc == 'ManageExchange':
            exc_type = self.__manage_exchange_type
            able = self.__manage_durable
        elif exc == 'GlobalExchange':
            exc_type = self.__global_exchange_type
            able = self.__global_durable
        else:
            exc_type = self.__flow_exchange_type
            able = self.__flow_durable
        try:
            r_rabbitmq = 'self.__r_' + str(domain) + 'rabbitmq'
            r_channel = 'self.__r_' + str(domain) + 'channel'
            globals()[r_rabbitmq] = pika.BlockingConnection(self.__rabbitmq)
            globals()[r_channel] = globals()[r_rabbitmq].channel()
        except Exception as err:
            log.warning('创建domain为: ' + str(domain) + ' 的接收管道失败!\n错误信息如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            globals()[r_channel].exchange_declare(exchange=exc, exchange_type=exc_type, durable=able)  # 连接交换机
        except Exception as err:
            log.warning('exchange=%s,exchange_type=%s,durable=%s' % {exc, exc_type, able})
            log.warning('交换机连接失败!可能是网络原因或配置信息错误.错误信息如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            globals()[r_channel].queue_bind(exchange=exc, queue=domain + '.up')
        except Exception as err:
            log.warning('queue绑定失败!可能是网络原因或配置信息错误.错误信息如下:')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
        try:
            if len(self.__thread_time.keys()) > 0:
                limit_time = 5
                for msg in globals()[r_channel].consume(domain + '.up', inactivity_timeout=0.0001,
                                                        auto_ack=True):  # 从Rabbitmq接收消息
                    if not msg:
                        if domain in self.__thread_time.keys():
                            if time.time() - self.__thread_time[domain] > limit_time:
                                try:
                                    globals()['self.__r_' + str(domain) + 'rabbitmq'].close()
                                except Exception as err:
                                    log.warning('Domain值为: ' + str(domain) + ' 的Rabbitmq信息接收管道关闭失败!\n错误信息如下:')
                                    log.warning(err)
                                    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                                else:
                                    del self.__domain[self.__domain.index(domain)]
                                    del self.__thread_time[domain]
                                    log.warning('Domain值为: ' + str(domain) + ' 的Rabbitmq信息接收管道关闭成功!')
                                    break
                            else:
                                continue
                        else:
                            break
                    else:
                        method, propertites, body = msg
                        if body:
                            with open(self.__logs_path + '/Logs/' + str(self.__version) + '/rabbitmq.logs', 'a',
                                      encoding='utf-8') as f:
                                msg = 'Domain: ' + str(domain) + ' Receive: ' + str(json.loads(body)) + '\n\n'
                                f.write(msg)
                        if domain in self.__thread_time.keys():
                            if time.time() - self.__thread_time[domain] > limit_time:
                                try:
                                    globals()['self.__r_' + str(domain) + 'rabbitmq'].close()
                                except Exception as err:
                                    log.warning('Domain值为: ' + str(domain) + ' 的Rabbitmq信息接收管道关闭失败!\n错误信息如下:')
                                    log.warning(err)
                                    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
                                else:
                                    del self.__domain[self.__domain.index(domain)]
                                    del self.__thread_time[domain]
                                    log.warning('Domain值为: ' + str(domain) + ' 的Rabbitmq信息接收管道关闭成功!')
                                    break
                            else:
                                continue
                        else:
                            break

                '''下面是线程阻断的接收方式'''
        # def callback(ch, method, properties, body):
        #	log.warning('收到数据：', json.loads(body))
        # globals()[r_channel].basic_consume(domain+'.up',callback,auto_ack=True)
        # globals()[r_channel].start_consuming()
        except Exception as err:
            log.warning('rabbitmq信息接收失败!错误信息如下: ')
            log.warning(err)
            sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

# if __name__ == '__main__':

# app=rabbitmq('10.10.88.4','admin','1qazxsw2#')
# app=rabbitmq('10.10.88.175','Admin','admin')
# app.connect()
# app.send('FlowExchange1','ReportFlow','10.10.88.175')
# app.close()
