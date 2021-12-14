'''
ftp相关命令操作
ftp.cwd(pathname) #设置FTP当前操作的路径
ftp.dir() #显示目录下文件信息
ftp.nlst() #获取目录下的文件
ftp.mkd(pathname) #新建远程目录
ftp.pwd() #返回当前所在位置
ftp.rmd(dirname) #删除远程目录
ftp.delete(filename) #删除远程文件
ftp.rename(fromname, toname)#将fromname修改名称为toname。
ftp.storbinaly("STOR filename.txt",file_handel,bufsize) #上传目标文件
ftp.retrbinary("RETR filename.txt",file_handel,bufsize)#下载FTP文件
'''
import csv
import ftplib
import logging
import os
import socket
import sys
from ftplib import FTP

log = logging.getLogger(__name__)


def connect_ftp(host, port, username, password):
    try:
        fp = FTP()
        fp.encoding = 'utf-8'
        # fp.set_debuglevel(2)  # 打开调试级别2，显示详细信息
        fp.set_debuglevel(0)  # 关闭调试信息
        fp.connect(host, port)  # 连接
        log.warning("*******已经成功连接'%s'服务器FTP服务！！！" % host)
    except(socket.error, socket.gaierror) as e:
        log.warning("错误：账密为'%s:%s'的用户，无法访问'%s:%d'服务器FTP服务！！！%s" % (username, password, host, port, e))
        return 0
    try:
        fp.login(username, password)  # 登录，如果匿名登录则用空串代替即可
        log.warning('ftp登录成功')
    except Exception:
        log.warning("ftp登录失败，请检查用户名【{}】和密码【{}】是否正确".format(username, password))
        return 0
    return fp


# 上传文件到ftp上
def uploadFile(fp, remotePath, localPath):
    try:

        # 创建ftp目录
        dirs = str(remotePath).split("/")
        curdir = ""
        for d in dirs:
            if (-1 != d.find(".")):
                break
            curdir = curdir + "/" + d
            log.warning("creat dir:" + curdir)
            try:
                fp.cwd(curdir)
            except Exception as e:

                log.warning('Error:{}'.format(e))
                fp.mkd(curdir)

        fp.cwd("/")

        bufsize = 1024  # 设置的缓冲区大小
        f = open(localPath, "rb")
        fp.storbinary("STOR %s" % remotePath, f, bufsize)  # 上传目标文件
        f.close()
        return 1
    except Exception as e:
        log.warning('Error:{}'.format(e))
        return 0


# 上传文件夹内的所有文件（包括文件和文件夹）
def uploadFileAll(fp, localDir):
    try:
        for root, dirs, files in os.walk(localDir, topdown=True):
            relative = root[len(localDir):].lstrip(os.sep)
            for d in dirs:
                fp.mkd(os.path.join(relative, d))

            for f in files:
                filePath = os.path.join(localDir, relative, f)
                fp.cwd(relative)
                with open(filePath, 'rb') as fileObj:
                    fp.storbinary('STOR ' + f, fileObj)
                fp.cwd('/')
        fp.quit()
        return 1
    except Exception as e:
        log.warning('Error:{}'.format(e))
        return 0


# 上传文件夹内的所有文件夹（仅针对目录上传）
def UpLoadDir(fp, LocalDir, RemoteDir='/'):
    try:
        if os.path.isdir(LocalDir) == False:
            return False
        log.warning("LocalDir:" + LocalDir)
        LocalNames = os.listdir(LocalDir)
        log.warning("list:" + LocalNames)
        log.warning(RemoteDir)
        fp.cwd(RemoteDir)
        for Local in LocalNames:
            src = os.path.join(LocalDir, Local)
            if os.path.isdir(src):
                UpLoadDir(fp, Local, src)
            else:
                uploadFile(fp, src, Local)
        fp.cwd("..")
        return 1
    except Exception as e:
        log.warning('Error:{}'.format(e))
        return 0


# 下载文件夹内的所有文件夹（仅针对目录下载）
def DownDir(fp, RemoteDir, LocalDir):
    try:
        log.warning("remoteDir: " + RemoteDir)
        if os.path.isdir(LocalDir) == False:
            os.makedirs(LocalDir)
        fp.cwd(RemoteDir)
        RemoteNames = fp.nlst()
        log.warning("RemoteNames: ".format(RemoteNames))
        log.warning(str(fp.nlst(RemoteDir)))
        for file in RemoteNames:
            Local = os.path.join(LocalDir, file)
            if checkFileDir(fp, file):
                DownDir(fp, file, Local)
            else:
                downFile(fp, file, Local)
        fp.cwd("..")
        return 1
    except Exception as e:
        log.warning('Error:{}'.format(e))
        return 0


# 从ftp上下载文件
def downFile(fp, remotePath, localPath):
    bufsize = 1024  # 设置的缓冲区大小

    try:
        f = open(localPath, "wb")
        fp.retrbinary("RETR %s" % remotePath, f.write, bufsize)  # 下载目标文件
        # fp.quit()  # 退出ftp
        f.close()
        return 1
    except Exception as e:
        log.warning('Error:{}'.format(e))
        # fp.quit()
        return 0


# 获取目录下文件或文件夹的列表信息，并清洗去除“. ..”
def nlstListInfo(fp):
    files_list = fp.nlst()
    return [file for file in files_list if file != "." and file != ".."]


# 判断文件与目录
def checkFileDir(ftp, file_name):
    rec = ""
    try:
        rec = ftp.cwd(file_name)  # 需要判断的元素
        ftp.cwd("..")  # 如果能通过路径打开则为文件夹，在此返回上一级
    except ftplib.error_perm as e:
        rec = e  # 不能通过路径打开必为文件，抓取其错误信息
    finally:
        if "550 Failed to change directory" in str(rec):
            return "File"
        elif "250 Directory successfully changed" in str(rec):
            return "Dir"
        else:
            return "Unknow"


# 删除目录下的所有文件（文件夹不删除，直接跳过）
def deleallFile(fp, Path, filename=None):
    try:
        try:
            fp.cwd(Path)
        except ftplib.error_perm:
            log.warning('无法进入目录：{}'.format(Path))
        # log.warning("当前所在位置:{}".format(fp.pwd()))  # 返回当前所在位置
        ftp_f_list = fp.nlst()  # 获取目录下文件、文件夹列表
        # log.warning('该路径{}下包含以下内容：{}'.format(fp.pwd(), ftp_f_list))
        if (filename in ftp_f_list) and (filename != None):
            fp.delete(filename)  # 删除文件
            log.warning("{}已删除！".format(filename))
            fp.close()
            return 1
        elif filename == None:
            filelist = nlstListInfo(fp)
            log.warning(filelist)
            tmp = []
            for i in filelist:
                if checkFileDir(fp, i) == "File":
                    fp.delete(i)  # 删除文件
                    log.warning("{}是文件，已删除！".format(i))
                    tmp.append(i)
                elif checkFileDir(fp, i) == "Dir":
                    log.warning("{}是文件夹".format(i))
                else:
                    log.warning("{}无法识别，跳过".format(i))
            log.warning(tmp)
            fp.close()
            if tmp != []:
                return 1
        else:
            log.warning("{}未找到，删除中止！".format(filename))
    except Exception as e:
        log.warning('Error:{}'.format(e))
        # fp.quit()
        return 0


# 查询本地文件内容
def show_file_content(filepath):
    # 获取文件类型
    fileType = filepath.split('.')[-1]

    # 如果文件是txt
    if 'txt' == fileType:
        textFile = open(filepath)
        lines = textFile.readlines()
    # csv文件内容读取
    elif 'csv' == fileType:
        csvFile = open(filepath)
        lines = csv.reader(csvFile)
    else:
        log.warning('无该类型文件的读取')
        sys.exit(0)
    return lines


if __name__ == '__main__':
    host = '192.168.30.47'
    # host = '192.168.30.111'
    port = 2121
    # host = '10.10.101.193'
    # port = 21
    username = 'test'
    # username = 'lwq'
    password = '1q2w3e'
    path = '/home/ftp/ftp_auto/ftp_del'
    # filename = 'utmp2log-0.0.22.tar.gz'
    upremotePath = '/home/ftp/ftp_auto/1.pdf'
    uplocalPath = 'C:/Users/admin/Desktop/work/1.pdf'

    downremotePath = '/home/ftp/ftp_auto/test.txt'
    downlocalPath = 'C:/Users/admin/Desktop/work/test.txt'

    localDir = 'C:\\Users\\admin\\Desktop\\work\\down_dir\\'
    remoteDir = '/home/ftp/ftp_auto/ftp_down_dir'

    # fp = connect_ftp(host, port, username, password)
    # log.warning('欢迎语是：{}'.format(fp.getwelcome()))
    # assert '220' in fp.getwelcome()
    # log.warning(fp)
    # log.warning('-------------------------------')
    # result = deleallFile(fp, baseinfo.ftp_delePath)
    # log.warning(result)
    # log.warning('-------------------------------')
    # result1 = downFile(fp, downremotePath, downlocalPath)
    # log.warning(result1)
    # log.warning('-------------------------------')
    # result = uploadFile(fp, upremotePath, uplocalPath)
    # log.warning(result)
    # log.warning('-------------------------------')
    # result = uploadFileAll(fp, upremotePath, localDir)
    # log.warning(result)
    # log.warning('-------------------------------')
    # result2 = DownDir(fp, remoteDir, localDir)
    # log.warning(result2)

    filepath = 'C:\\Users\\admin\\Desktop\\work\\zp.txt'
    result = show_file_content(filepath)
    log.warning(result)

    # # 列出
    # ls = nlstListInfo(fp)
    # log.warning('ls:{}'.format(ls))
