#!/usr/bin/env python
# -*- coding:utf-8 -*-
#。——————————————————————————————————————————
#。
#。  ftclient.py
#。
#。 @Time    : 2018/7/26 00:09
#。 @Author  : ccapton (original)
#。 @Software: PyCharm
#。 @Github  : https://github.com/ccapton
#。 @Email   : chenweibin1125@foxmail.com
#。 经过后期改写和调整。
#。 该程序的连接原理是：先建立与数据端口的连接，再建立到命令端口的连接，然后通过命令端口传输数据。
#。 很奇怪，我也不知道为什么要这么做。
#。__________________________________________



import sys
import socket
import threading
import argparse

from list_file import *
from util import relative_path,dir_divider,checkfile,formated_size,formated_time,getFileMd5

from  language_words import languageSelecter

python_version = "3"

divider_arg =  ' _*_ '
right_arrows = '>'*10
left_arrows = '<'*10

msg_index = 0

isCommandTConnected= False

default_data_socket_port = 5105
default_command_socket_port = 5104


COMMAND_CLOSE = '[COMMAND CLOSE]'
COMMANE_MISSION_SIZE = '[COMMAND MISSION_SIZE]'
COMMANE_FILE_INFO = '[COMMAND FILE_INFO]'
COMMANE_DATA_PORT = '[COMMAND DATA_PORT]'

task_id = "fde8e8" # test

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
                if self.send_debug:print(dict('ce'))
        elif self.send_debug:print(dict('sin'))
        return self

    def recv_msg(self):
        if self.socket:
            try:
                msg = self.socket.recv(1024)
                return bytes(msg).decode('utf8')
            except Exception as e:
                if self.recev_debug:print(dict('ce'))
        elif self.recev_debug:  print(dict('sin'))
        return None


class CommandThread(threading.Thread):
    def __init__(self, host=None, port=default_command_socket_port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.working = True
        self.messenger = None
        self.start_time = 0

    def setMissionSize(self,mission_size):
        self.mission_size = mission_size

    def setDataThread(self, server):
        self.dataThread = server

    def run(self):
        self.socket = socket.socket()
        try:
            self.socket.connect((self.host, self.port))
            global isCommandTConnected
            isCommandTConnected = True
            self.messenger = Messenger(self.socket)
            try:
                command = self.messenger.recv_msg()
                print(f"L98: {command}")

                if self.working:
                   self.start_time = time.time()
                   print(command)

                self.messenger.send_msg(COMMANE_DATA_PORT)

                data_port = self.messenger.recv_msg()

                self.dataThread.port = int(data_port)
                self.dataThread.start()

                self.messenger.send_msg(COMMANE_MISSION_SIZE + divider_arg + str(self.mission_size))

                while self.working and command and len(command) > 0:
                    if command.endswith('rootdir_create_ok'):
                        self.dataThread.waitingCreateDir = False
                    elif command.endswith('file_transport_ok') or command.endswith('dir_create_ok'):
                        self.dataThread.filefinder.recycle = False
                    elif command.endswith('file_existed'):
                        self.dataThread.filefinder.recycle = False
                        print(dict('fe') + ' ' + command.split(divider_arg)[1])
                        if self.dataThread.findfileOver:
                            self.send_command(COMMAND_CLOSE)
                            self.socket.close()
                            self.working = False
                            print(dict('cmct') + '%s' % formated_time(time.time() - self.start_time))
                    elif command.endswith('ready'):
                        self.dataThread.send_filedata()
                    command = self.messenger.recv_msg()
                    if not self.working:
                        if sumsize == self.dataThread.sumsize:
                            print(right_arrows+dict('mc')+left_arrows)
                        self.socket.close()
            except ConnectionResetError as e:
                self.working = False
                if self.dataThread.filefinder:
                    self.dataThread.filefinder.finderCallback = None
                    self.dataThread.filefinder.recycle = True
                    self.dataThread.filefinder.off = True
                self.socket.close()
                self.dataThread.socket.close()
                print(right_arrows+dict('ci')+left_arrows)
                print(' %s...' % dict('pttmoa'))
            except OSError as e:
                print('%s(%s)' % (dict('nrth'),self.host))
            except Exception as e:
                print(e)
        except Exception:
            warning(right_arrows+dict('ce')+left_arrows)


    def send_fileinfo(self,fileinfo):
        if self.messenger:
            self.messenger.send_msg(fileinfo)

    def send_command(self,msg):
        if self.messenger:
            self.messenger.send_msg(msg)


class Client(threading.Thread , FileFinder.FinderCallback):
    def __init__(self,host):
        threading.Thread.__init__(self)
        self.filefinder = None
        self.host = host
        self.port = None # dataport
        self.singFile = True
        self.findfileOver = False
        self.sumsize = 0
        self.mission_read_size = 0
        self.waitingCreateDir = True
        self.once = True


    def setCommandThread(self, commandThread):
        self.commandThread = commandThread


    def setFilePath(self,filepath):
        self.filepath = filepath
        self.rootpath = filepath


    def onFindDir(self,dir_path):
        global msg_index
        msg_index += 1
        print(dict('cd')+ os.path.basename(self.rootpath)+dir_divider()+relative_path(self.rootpath,dir_path))
        self.filename = dir_path
        self.filesize = -1
        self.commandThread.send_fileinfo(COMMANE_FILE_INFO + divider_arg + task_id + divider_arg
                                         +os.path.basename(self.rootpath) + dir_divider()+relative_path(self.rootpath,dir_path)+ divider_arg
                                         +str(-1)+divider_arg+
                                         str(msg_index))
        print(self.commandThread.messenger.recv_msg())

    def onFindFile(self,file_path,size):
        global msg_index
        msg_index += 1
        print(dict('tf')+ os.path.basename(self.rootpath)+dir_divider()+relative_path(self.rootpath,file_path) +
              ' '+ formated_size(size))
        print(f"L182: {os.path.basename(self.rootpath)+dir_divider()+relative_path(self.rootpath,file_path)}")
        self.filename = file_path
        print(f"L183: {self.filename}")
        self.filesize = size
        if (os.path.isfile(file_path) and relative_path(self.rootpath,file_path) == ''):
            self.commandThread.send_fileinfo(COMMANE_FILE_INFO + divider_arg + task_id + divider_arg +
                                             os.path.basename(file_path) + divider_arg+
                                             str(size) + divider_arg+
                                             getFileMd5(file_path) + divider_arg+
                                             str(msg_index))
        else:
            self.commandThread.send_fileinfo(COMMANE_FILE_INFO + divider_arg + task_id + divider_arg +
                                             os.path.basename(self.rootpath) + dir_divider()+ relative_path(self.rootpath,file_path) + divider_arg+
                                             str(size) + divider_arg +
                                             getFileMd5(file_path) + divider_arg +
                                             str(msg_index))
        print(self.commandThread.messenger.recv_msg())

    def run(self):
        if checkfile(self.filepath)[0] and checkfile(self.filepath)[1] == 1:
            self.singFile = True
            if self.connect_to_server():
                self.filefinder = FileFinder(self)
                self.filefinder.recycle = False
                self.filefinder.list_flie(self.filepath)
        elif checkfile(self.filepath)[0] and checkfile(self.filepath)[1] == 0:
            self.singFile = False
            self.findfileOver = False
            if self.connect_to_server():
                print(dict('cd') + os.path.basename(self.filepath))
                print(f"L209: {os.path.basename(self.filepath)}")
                self.commandThread.send_command(COMMANE_FILE_INFO + divider_arg + task_id + divider_arg +
                                                os.path.basename(self.filepath) + divider_arg +
                                                '-1' +divider_arg
                                                + str(msg_index))
                # if (return_msg:=self.commandThread.messenger.recv_msg()) != "OK":
                #     print(f"ERROR: {return_msg}")
                #     sys.exit()
                # divider_arg 用的符号不能当文件名，所以确实可以把 _*_ 当分隔符
                # 但是老哥这样简单粗暴地写真的好吗？
                while self.waitingCreateDir:
                    time.sleep(0.1)
                self.waitingCreateDir = True
                self.filefinder = FileFinder(self)
                self.filefinder.recycle = False
                self.filefinder.list_flie(self.filepath)
                self.findfileOver = True
        elif not checkfile(self.filepath)[0]:
            print(dict('picf'))


    def connect_to_server(self):
        self.socket = socket.socket()
        try:
            self.socket.connect((self.host, self.port))
            print(bytes(self.socket.recv(1024)).decode(encoding='utf8'))
            print(right_arrows+dict('ms')+left_arrows)
            print('-'*30)
            return True
        except ConnectionError as e:
            if isCommandTConnected:
                print('%s %d' % (dict('tsbd'),self.port))
                print(right_arrows+dict('cd')+left_arrows)
                self.commandThread.messenger.send_msg(COMMAND_CLOSE)
                self.commandThread.socket.close()
                self.commandThread.working = False
            else:
                warning(right_arrows+dict('ce')+ left_arrows+
                  ' \n %s\n %s\n ' % (dict('pct'),dict('octs'))+
                  '%s ( %s , %d )' % (dict('thap'),self.host,self.port))
        except OSError as e:
            print('%s(%s)' % (dict('nrth'),self.host))
        return False


    def send_filedata(self):
        readed_size = 0
        with open(self.filename,'rb') as f:
            filedata = f.read(4096)
            while len(filedata) > 0 :
                tempsize = len(filedata)
                readed_size += tempsize
                self.mission_read_size += tempsize
                try:
                   # print(f"L260： {filedata}")
                   self.socket.send(filedata)
                   readed_show = '%s/%s' % (formated_size(readed_size),formated_size(self.filesize))
                   total_readed_show = '%s/%s' % (formated_size(self.mission_read_size),formated_size(sumsize))
                   current_filename = os.path.basename(self.filename) + ' '
                   sys.stdout.write(current_filename + readed_show + ' | %.2f%%  >>>%s %s | %.2f%%' %
                                    (float(readed_size / self.filesize * 100),
                                     dict('total'),
                                     total_readed_show,
                                     float(self.mission_read_size / sumsize * 100)) + '\r')
                except BrokenPipeError as e:
                    if self.once:
                        if self.filefinder:
                            self.filefinder.finderCallback = None
                            self.filefinder.recycle = True
                            self.filefinder.off = True
                        print(right_arrows+dict('rcd')+left_arrows)
                        self.once = False
                filedata = f.read(4096)
        print()
        if  readed_size == self.filesize and readed_size == 0:
            print(os.path.basename(self.filename) + ' %s' % dict('fi') )
        print('—'*30)
        if self.singFile:
            self.commandThread.send_command(COMMAND_CLOSE)
            self.socket.close()
            self.commandThread.working = False
            print(dict('cmct') + '%s' % formated_time(time.time() - self.commandThread.start_time))
        else:
            if self.findfileOver:
                self.commandThread.send_command(COMMAND_CLOSE)
                self.socket.close()
                self.commandThread.working = False
                print(dict('cmct')+'%s' % formated_time(time.time() - self.commandThread.start_time))


class MyfinderCallback(FileFinder_Fast.FinderCallback):
    def __init__(self):
        self.sumsize = 0
    def onFindDir(self,dir_path):
        pass
    def onFindFile(self,file_path,size):
        self.sumsize += size

def keyInPort():
    while True:
        temp_port = input(dict('ip'))
        if int(temp_port) > 0 and int(temp_port) != default_command_socket_port:
            return (int(temp_port),True)
        elif int(temp_port) <= 0:
            warning(dict('pmb'))
        elif int(temp_port) == default_command_socket_port:
            warning('%s %d %s,%s' % (dict('po'),dict('id'),default_command_socket_port,dict('pki')))

def keyInFilePath():
    while True:
        filepath = input(dict('pif'))
        if filepath.endswith(dir_divider()):
            filepath2 = filepath[:len(filepath)-1]
        else:
            filepath2 = filepath
        if checkfile(filepath2)[0]:
            return filepath2, True
        else:
            print(dict('pde'))

def keyInHost():
    while True:
        host = input(dict('pit'))
        if len(host) > 0:
            return host, True

def warning(text):
    print('[%s] ' % dict('wa')+text)

def dict(key):
   return languageSelecter.dict(key)

def print_author_info(program_name):
    print('*'*60)
    line = 9
    while line > 0:
      if line == 8:
          print('。  %s' % program_name)
      elif line == 6:
          print('。  @ %s: Capton' % dict('Author'))
      elif line == 5:
          print('。  @ %s: http://ccapton.cn' % dict('Blog'))
      elif line == 4:
          print('。  @ %s: chenweibin1125@foxmail.com' % dict('Email'))
      elif line == 3:
          print('。  @ %s: https://github.com/ccapton' % dict('Github'))
      elif line == 2:
          print('。  @ %s: https://github.com/Ccapton/python-stuff/tree/master/filetransporter' % dict('Project'))
      else:
          print('。')
      line -= 1
    print('*'*60)

if __name__ == '__main__':
    # python ft_client -f /Users/capton/desktop/test.mp4 -i 127.0.0.1 -p 5050'

    print_author_info(dict('ftcp'))

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filepath', required=False, help=(dict('tpws')))
    parser.add_argument('-p', '--port', required=False, help=(dict('tptp')),type = int)
    parser.add_argument('-i', '--host', required=False, help=(dict('thtp')),type = str)

    args = parser.parse_args()

    port = default_data_socket_port

    filepath_ok = True
    port_ok = True
    host_ok = False
    if args.port and args.port > 0 :
        port = args.port
        if port == default_command_socket_port:
            warning('%s %d %s,%s' % (dict('po'),default_command_socket_port,dict('id'),dict('pki')))
            port , port_ok = keyInPort()
    elif args.port and args.port <=0:
        warning(dict('pmb'))
        port, port_ok = keyInPort()

    filepath = args.filepath
    if not filepath:
        filepath , filepath_ok = keyInFilePath()
    elif not checkfile(args.filepath)[0]:
        warning(dict('pde'))
        filepath , filepath_ok = keyInFilePath()

    host = args.host
    if not host:
        host , host_ok = keyInHost()
    else:
        host_ok = True

    if port_ok and filepath_ok and host_ok:
        findercallback = MyfinderCallback()
        if not checkfile(filepath)[1]:
           print('%s %s' % (dict('ffi'),filepath))
        FileFinder_Fast(findercallback).list_flie(filepath)
        global sumsize
        sumsize = findercallback.sumsize
        file_type = ''
        if checkfile(filepath)[1]:
            file_type = dict('tf')
        else:
            file_type = dict('td')
        warning('%s %s' % (dict('ya'),file_type))
        print(filepath + ' | %s%s : %s' % (dict('total'),dict('si'),formated_size(sumsize)))

        confirm = input('%s(Y/N):'% dict('ct'))
        while True:
            if confirm == 'y' or confirm == 'Y' or confirm == 'Yes'.upper() or confirm == 'yes'.lower():
                commandThread = None
                client = Client(host) # no port
                commandThread = CommandThread(host, default_command_socket_port)
                commandThread.setDataThread(client)
                commandThread.setMissionSize(sumsize)
                client.setCommandThread(commandThread)
                client.setFilePath(filepath)
                # client.start()
                commandThread.start()
                break
            elif confirm == 'n' or confirm == 'N' or confirm == 'No'.upper() or confirm == 'no'.lower():
                warning(dict('gvm'))
                break
            confirm = input('%s(Y/N):' % dict('ct'))

