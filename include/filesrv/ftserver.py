#!/usr/bin/env python
# -*- coding:utf-8 -*-
#。——————————————————————————————————————————
#。
#。  ftserver.py
#。
#。 @Time    : 2018/7/26 00:09
#。 @Author  : ccapton (original)
#。 @Software: PyCharm
#。 @Github  : https://github.com/ccapton
#。 @Email   : chenweibin1125@foxmail.com
#。__________________________________________


import sqlite3
import sys,os
import socket
import threading

sys.path.append("./include/filesrv/")

from util import dir_divider,anti_dir_divider,checkfile,formated_time,formated_size,getFileMd5
import time

from language_words import languageSelecter
 
python_version = "3" # remove py2 support

divider_arg  = ' _*_ '
right_arrows = '>'*10
left_arrows  = '<'*10

default_data_socket_port = 5104
default_command_socket_port = 5105

COMMAND_CLOSE = '[COMMAND CLOSE]'
COMMANE_MISSION_SIZE = '[COMMAND MISSION_SIZE]'
COMMANE_FILE_INFO = '[COMMAND FILE_INFO]'
COMMAND_DATA_PORT = '[COMMAND DATA_PORT]'
COMMAND_REGISTER_FILE_ID = '[COMMAND REGISTER_FILE_ID]'


class Messenger:
    def __init__(self,socket):
        self.socket = socket
        self.send_debug = False
        self.recev_debug = False

    def send_msg(self,msg):
        if self.socket:
            try:
               self.socket.send(bytes(msg ,encoding='utf8'))
            except Exception as e:
                if self.send_debug:print(lang_dict('ce'))
        elif self.send_debug:print(lang_dict('sin'))
        return self

    def recv_msg(self):
        if self.socket:
            try:
                msg = self.socket.recv(1024)
                return bytes(msg).decode('utf8')
            except Exception as e:
                if self.recev_debug:print(lang_dict('ce'))
        elif self.recev_debug:  print(lang_dict('sin'))
        return None


class CommandThread(threading.Thread):
    def __init__(self, host=None, port=default_command_socket_port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.working = True
        self.dataOn = True
        self.wait_client_flag = True
        self.mission_size = 0
        self.wrote_size = 0
        self.start_time = 0

        self.this_time_task_id = None
        self.this_time_dest = None
        self.done = False
        self.singleFile = True
        self.this_time_filename = None


    def setDataThread(self, server):
        self.dataThread = server

    def run(self):
        self.ssocket = socket.socket()
        self.ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.ssocket.bind((self.host, self.port)) # command port
            self.ssocket.listen(1)
            while self.wait_client_flag:
                socket2, addr = self.ssocket.accept()
                self.socket = socket2
                self.socket.send(
                    # meaningless, but we can make it more meaningful
                    bytes(f"{lang_dict('ctcs')} {self.host}: {str(self.port)} {divider_arg} {self.dataThread.port}", encoding='utf8'))
                self.commandMessenger = Messenger(self.socket)
                command = self.commandMessenger.recv_msg()
                self.start_time = time.time()

                while command and len(command) and self.working> 0: # 主命令判断逻辑
                    if command.startswith(COMMANE_MISSION_SIZE):
                        self.mission_size = int(command.split(divider_arg)[1])
                        print(lang_dict('m_s')+': %s' % formated_size(self.mission_size))
                    elif command.startswith(COMMAND_REGISTER_FILE_ID):

                        fQueue_db = sqlite3.connect(ROOT_ABSPATH+"/content/fqueue.db")
                        # 没有额外执行检查的机制，因为这个操作应该早已完成
                        fQ_cur = fQueue_db.cursor()

                        given_task_id = command.split(divider_arg)[1]

                        fQ_cur.execute("select filename, destination FROM ft_queue WHERE task_id = ?", (given_task_id,))

                        task_details = fQ_cur.fetchall()

                        if len(task_details) > 1:
                            raise RuntimeError("数据库中记录了不止一个同id的传输任务")
                        elif len(task_details) < 1:
                            self.commandMessenger.send_msg("指定的任务不存在或已过期")
                        else:
                            self.this_time_task_id = given_task_id
                            self.this_time_filename, self.this_time_dest = task_details[0]
                            self.done = False
                            self.commandMessenger.send_msg("OK")
                    
                    elif command.startswith(COMMANE_FILE_INFO):
                        if self.singleFile and self.done:
                            self.commandMessenger.send_msg("该id指向一个单独的文件且已完成上传")
                            continue
                        
                        if not self.this_time_task_id:
                            self.commandMessenger.send_msg("尚未注册任务ID。")
                            continue

                        self.fileMission = FileMission(self.dataThread.socket, self, self.this_time_dest, command)
                        self.fileMission.start()
                        self.dataOn = True

                        self.commandMessenger.send_msg("OK")

                    elif command == COMMAND_DATA_PORT:
                        self.socket.send(bytes(str(self.dataThread.port), encoding="utf-8"))
                    elif command == COMMAND_CLOSE:
                        self.dataOn = False
                        time.sleep(0.3)
                        Warning(right_arrows+lang_dict('rcd')+left_arrows)
                    else:
                        self.commandMessenger.send_msg("Unknown command")
                    command = self.commandMessenger.recv_msg()
        except OSError:
            warning(lang_dict('cara'))
            self.wait_client_flag = False


    def file_ready(self,fileinfo):
        self.commandMessenger.send_msg(fileinfo + divider_arg +'ready')


    def file_transportover(self,fileinfo):
        self.commandMessenger.send_msg(fileinfo + divider_arg +'file_transport_ok')


    def file_existed(self,fileinfo):
        self.commandMessenger.send_msg(fileinfo + divider_arg + 'file_existed')


    def dir_created(self,fileinfo):
        self.commandMessenger.send_msg(fileinfo + divider_arg +'dir_create_ok')


    def rootdir_create(self,fileinfo):
        self.commandMessenger.send_msg(fileinfo + divider_arg +'rootdir_create_ok')


class Server(threading.Thread):
    def __init__(self,save_path,host = None,port = 9997):
        threading.Thread.__init__(self)
        self.save_path = save_path
        self.host = host
        self.port = int(port)
        self.wait_client_flag = True
        if not os.path.exists(self.save_path):
            os.makedirs(self.save_path)
        print(lang_dict('fsd') + self.save_path)


    def setCommandThread(self,commandThread):
        self.commandThread = commandThread

    def run(self):
        self.start_server_socket()
        self.wait_client()


    def start_server_socket(self):
        self.ssocket = socket.socket()
        self.ssocket.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE, True)
        try:
            self.ssocket.bind((self.host, self.port))
            print(lang_dict('shs'))
            print(lang_dict('ra')+' (%s,%d)' % (self.host, self.port))
            print(lang_dict('wfft')+'...')
        except OSError:
            self.wait_client_flag = False
            pass


    def wait_client(self):
        self.ssocket.listen()
        while self.wait_client_flag:
            print("waiting")
            socket, addr = self.ssocket.accept()
            print("accepted new connection")
            print(lang_dict('nc'), addr)
            try:
                socket.send(bytes(lang_dict('ctds') + self.host + ':' + str(self.port), encoding="utf8"))
                self.socket = socket
                self.commandThread.setDataThread(self)
                self.commandThread.dataOn = True
            except ConnectionResetError as e:
                print(lang_dict('aoc')+'\n')
                print(lang_dict('wfft')+'...')
            print("done")


class FileMission(threading.Thread):
    def __init__(self,socket,commandThread,save_path,fileinfo):
        threading.Thread.__init__(self)
        self.commandThread = commandThread
        self.socket = socket
        self.save_path = save_path # CommandThread -> Server(DataThread).save_path -> FileMission
        self.fileinfo = fileinfo
        self.working = True

    def run(self):
        self.handleMission()


    def handleMission(self):
        if self.fileinfo:
            print(self.fileinfo)
            self.filename = self.fileinfo.split(divider_arg)[1]
            print(self.filename)
            self.filename = self.filename.replace(anti_dir_divider(), dir_divider())
            print(self.filename)
            self.file_path = str(self.save_path + dir_divider() + self.filename)
            self.file_path = self.file_path.replace(anti_dir_divider(), dir_divider())
            self.filesize = int(self.fileinfo.split(divider_arg)[2])
        if self.filesize >= 0:
            self.file_md5 = self.fileinfo.split(divider_arg)[3]
            self.write_filedata()
        elif self.filesize == -1:
            if not os.path.exists(self.file_path):
                os.makedirs(self.file_path)
            index = int(self.fileinfo.split(divider_arg)[3])
            dir = self.fileinfo.split(divider_arg)[1]

            if index == 0:
                print(right_arrows+lang_dict('ms')+left_arrows)
                print('-' * 30)
                self.commandThread.rootdir_create(self.fileinfo)
            else:
                self.commandThread.dir_created(self.fileinfo)
            print(lang_dict('cd')+': ' + dir)


    def write_filedata(self):
        print(lang_dict('st')+'%s %s' % (self.filename,formated_size(self.filesize)))

        if getFileMd5(self.file_path) == self.file_md5:
            print(lang_dict('fe') + self.filename)
            self.commandThread.wrote_size += self.filesize
            self.commandThread.file_existed(self.fileinfo)
            downloaded_show = '%s/%s' % (formated_size(self.filesize), formated_size(self.filesize))
            total_downloaded_show = '%s/%s' % (formated_size(self.commandThread.wrote_size),
                                               formated_size(self.commandThread.mission_size))
            current_filename = os.path.basename(self.filename) + ' '
            print(current_filename + downloaded_show + ' | %.2f%%  >>>%s %s | %.2f%%' %
                             (float(self.filesize / self.filesize * 100),
                              lang_dict('total'),
                              total_downloaded_show,
                              float(self.commandThread.wrote_size / self.commandThread.mission_size * 100)) + '\r')
            print('-' * 30)
            if self.commandThread.wrote_size == self.commandThread.mission_size and self.commandThread.wrote_size != 0:
                self.commandThread.wrote_size = 0
                self.commandThread.mission_size = 0
                print(right_arrows + lang_dict('mc') + left_arrows)
                print(lang_dict('cmct') + '%s' % formated_time(time.time() - self.commandThread.start_time))
                print(
                    lang_dict('ra') + ' (%s,%d)' % (self.commandThread.dataThread.host, self.commandThread.dataThread.port))
                print(lang_dict('wfft') + '...')
            return


        if self.filesize == 0:
            with open(self.file_path, 'wb') as f:
                pass
            self.commandThread.file_existed(self.fileinfo)
            return


        self.commandThread.file_ready(self.fileinfo)


        with open(self.file_path,'wb') as f:
            wrote_size = 0
            filedata = self.socket.recv(4096)
            while len(filedata) > 0 :
                tempsize = f.write(filedata)
                wrote_size += tempsize
                self.commandThread.wrote_size += tempsize
                f.flush()
                downloaded_show = '%s/%s' % (formated_size(wrote_size),formated_size(self.filesize))
                total_downloaded_show = '%s/%s' % (formated_size(self.commandThread.wrote_size),
                                                   formated_size(self.commandThread.mission_size))
                current_filename = os.path.basename(self.filename) +' '
                sys.stdout.write(current_filename + downloaded_show +' | %.2f%%  >>>%s %s | %.2f%%' %
                                 (float(wrote_size / self.filesize * 100),
                                  lang_dict('total'),
                                  total_downloaded_show,
                                  float(self.commandThread.wrote_size / self.commandThread.mission_size * 100))+ '\r')
                if wrote_size == self.filesize:
                    print()
                    print(self.filename + ' ' + lang_dict('dd'))

                    self.commandThread.file_transportover(self.fileinfo)

                    if not self.commandThread.dataOn:
                        self.socket.close()
                    break
                else:
                    try:

                        filedata = self.socket.recv(4096)
                    except ConnectionResetError:

                        warning(right_arrows+ lang_dict('rcd')+left_arrows)


            if wrote_size < self.filesize:
                warning(right_arrows+lang_dict('ci')+left_arrows)
                self.dataOn = False
                self.socket.close()
                self.commandThread.socket.close()
                self.commandThread.wrote_size = 0
                self.commandThread.mission_size = 0

            print('-'*30)

            if self.commandThread.wrote_size == self.commandThread.mission_size and self.commandThread.wrote_size != 0:
                self.commandThread.wrote_size = 0
                self.commandThread.mission_size = 0
                print(right_arrows+lang_dict('mc')+left_arrows)
                print(lang_dict('cmct')+'%s' % formated_time(time.time() - self.commandThread.start_time))
                print(lang_dict('ra')+' (%s,%d)' % (self.commandThread.dataThread.host, self.commandThread.dataThread.port))
                print(lang_dict('wfft')+'...')

def warning(text):
    print('[%s] '% lang_dict('wa')+text)

def keyInPort():
    while True:
        temp_port = input(lang_dict('ip'))
        if int(temp_port) > 0 and int(temp_port) != default_command_socket_port:
            return (int(temp_port),True)
        elif int(temp_port) <= 0:
            warning(lang_dict('pmb'))
        elif int(temp_port) == default_command_socket_port:
            warning('Port %d is disabled,please key in other number' % default_command_socket_port)


def keyInSavePath():
    while True:
        filepath = input(lang_dict('pidp'))
        if checkfile(filepath)[0] and checkfile(filepath)[1] == 0:
            return filepath, True
        elif not checkfile(filepath)[0]:
            warning(lang_dict('pde'))
        elif checkfile(filepath)[0] and checkfile(filepath)[1] == 1:
            warning(lang_dict('dpif'))


def keyInHost():
    while True:
        host = input(lang_dict('pit'))
        if len(host) > 0:
            return host, True

def lang_dict(key):
    return languageSelecter.dict(key)

def __main__(host, fc_port, fd_port, root_abspath):
    print("ft_srv 被调用")

    global ROOT_ABSPATH
    ROOT_ABSPATH = root_abspath

    commandThread = CommandThread(host=host, port=fc_port)
    server = Server(save_path=ROOT_ABSPATH+"/content/files", host = host, port=fd_port)
    server.setCommandThread(commandThread)
    server.start()
    commandThread.setDataThread(server)
    commandThread.start()



