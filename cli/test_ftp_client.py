# 仅供测试。

from ftplib import FTP, FTP_TLS

ftp = FTP_TLS()  # connect to host, default port

ftp.connect("localhost", 5104)

ftp.login("", "")                     # user anonymous, passwd anonymous@

ftp.cwd('debian')               # change into "debian" directory

ftp.retrlines('LIST')           # list directory contents






with open('README', 'wb') as fp:
    ftp.retrbinary('RETR README', fp.write)

# ftp.quit()