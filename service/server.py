#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

import logging
import time
from daemons.prefab import run
import socket
import ssl
import json
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import sys
import subprocess
import os
from threading import Timer

# Default uses development config file
# If prod argument passed would change to config_server.json
DEV = True
CONFIG_FILE = "config/config_server_dev.json"
LOGGING_LEVEL = logging.DEBUG



class DaemonServer(run.RunDaemon):
    """
    Server daemon run method that listens on a SSL/TLS socket connection for encrypted AES message only from known server known_srv_ip
    When a message comes, will call the DoorOpener class to validate data and execute the new rule
    """

    def __init__(self, host_srv, port_srv, known_srv_ip, ssl_cert_file, ssl_key_file, aes_key, api_key, **kwargs):
        self.host_srv = host_srv
        self.port_srv = port_srv
        self.known_srv_ip = known_srv_ip
        self.ssl_cert_file = ssl_cert_file
        self.ssl_key_file = ssl_key_file
        self.aes_key = aes_key
        self.api_key = api_key
        super(DaemonServer, self).__init__(**kwargs)

    def run(self):
        logger.debug('DaemonServer run method started')
        try:
            ipAddr = socket.gethostbyname(self.host_srv)
            logger.debug("Listening on IP = {} - {}  and PORT = {}".format(ipAddr, self.host_srv, str(self.port_srv)))
        except socket.gaierror:
            logger.debug("Host name could not be resolved")

        err = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.debug('Socket created')
            s.bind((self.host_srv, self.port_srv))
            logger.debug("Bind worked")
            s.listen(1)
            logger.debug("Listen worked")
        except Exception as e1:
            logger.debug("Failed to create socket: " + repr(e1))
            err = True

        if not err:
            # Creates a new DoorOpener instance that will be used at the main loop
            opener = DoorOpener(self.api_key)
            # Flush all rules at startup
            opener.do_action('{"action":"flush"}')
            # aes class for decrypt message
            aes = AESCipher(self.aes_key)
            # MAIN LOOP
            logger.info('STARTING INFINTE LOOP')
            while True:
                try:
                    response = False
                    message = False
                    # At here the program stops until a new client request
                    conn, addr = s.accept()
                    ssl_socket = ssl.wrap_socket(conn, keyfile=self.ssl_key_file, certfile=self.ssl_cert_file,
                                                 cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2, server_side=True)
                    logger.debug("SSLSocket peername: {}".format(repr(ssl_socket.getpeername())))
                    logger.debug("SSLSocket cipher: {}".format(ssl_socket.cipher()))
                    logger.debug("SSLSocket ssl version: {}".format(ssl_socket.ssl_version))
                    logger.info("ACCEPTED CONNECTION from {}".format(str(addr)))
                    if str(addr[0]) != self.known_srv_ip:
                        raise Exception("INVALID known_srv_ip {}".format(str(addr)))

                    raw = ssl_socket.recv()
                    message = aes.decrypt(raw.decode())
                    if message:
                        response = opener.do_action(message)
                except KeyError as e1:
                    logger.error("{} not in message".format(str(e1)))
                except Exception as e2:
                    logger.error("!!! {}".format(str(e2)))
                finally:
                    try:
                        if response:
                            ssl_socket.sendall('OK'.encode())
                        else:
                            ssl_socket.sendall('FAIL'.encode())
                        ssl_socket.shutdown(how=socket.SHUT_RDWR)
                        ssl_socket.close()
                    except Exception as e3:
                        logger.error("Error closing socket " + str(e3))
                time.sleep(0.25)

        logger.info("Exiting daemon main loop")

class DoorOpener:
    """
    Class that executes iptables command to permit connections to LAN devices from a specific ip.
    Makes a new rule in the NAT table of the router to forward a port to a internal private ip
    Also checks and validates the message payload and needed data
    Needs:
        - ip_src: the authorized IP from the connection will come
        - port_dst: the router port that will be forwarded to LAN
        - ip_dst_lan: internal LAN device ip
        - action: add or del a rule, flush all rules
        - api_key: client verification
    Optional:
        - rule_timeout: amount of time the NAT rule will be applied (default: 5 minutes)
        - port_dst_lan: internal LAN device port (default: same than port_dst)

    Command :
        iptables -t nat -I PREROUTING -s <ip_source>/32 -p tcp -m tcp --dport <port_src> -j DNAT --to-destination <ip_dst>:<port_dst>

    """

    def __init__(self, api_key):
        self.rule_timeout = 5
        self.api_key = api_key

    def read_data(self):
        self.action = self.message["action"]
        if self.action == "flush":
            return
        self.ip_src = self.message["ip_src"]
        self.port_dst = self.message["port_dst"]
        self.ip_dst_lan = self.message["ip_dst_lan"]
        self.api_key = self.message["api_key"]

        if "port_dst_lan" in self.message.keys():
            self.port_dst_lan = self.message["port_dst_lan"]
        else:
            self.port_dst_lan = self.port_dst

        if "rule_timeout" in self.message.keys():
            self.rule_timeout = self.message["rule_timeout"]

    def validate_data(self, msg):
        self.message = json.loads(msg)
        logger.debug("data : " + str(self.message))

        if self.message["action"] != None and self.message["action"] == "flush":
            return True

        if self.message["action"] != None and self.message["ip_src"] != None and self.message["port_dst"] != None \
                and self.message["ip_dst_lan"] != None  and self.message["api_key"] != None:
            pass
        else:
            raise Exception("No all needed data specified")
        try:
            socket.inet_aton(self.message["ip_src"])
        except Exception:
            raise Exception("IP_SOURCE [ {} ] is INVALID".format(str(self.message["ip_src"])))
        try:
            socket.inet_aton(self.message["ip_dst_lan"])
        except Exception:
            raise Exception("IP_DST_LAN [ {} ] is INVALID".format(str(self.message["ip_dst_lan"])))

        if self.message["port_dst"] not in range(1024, 65535):
            raise Exception("PORT_DST [ {} ] is INVALID".format(str(self.message["port_dst"])))

        if self.message["action"] not in ["add", "del"]:
            raise Exception("ACTION [ {} ] is INVALID".format(str(self.message["action"])))

        if self.message["api_key"] != self.api_key:
            raise Exception("API_KEY [ {} ] is INVALID".format(str(self.message["api_key"])))

        if "port_dst_lan" in self.message.keys():
            if self.message["port_dst_lan"] not in range(0, 65535):
                raise Exception("PORT_DST_LAN [ {} ] is INVALID".format(str(self.message["port_dst_lan"])))
        if "rule_timeout" in self.message.keys():
            if self.message["rule_timeout"] not in range(1, 999):
                raise Exception("TIME [ {} ] is INVALID".format(str(self.message["rule_timeout"])))

        return True

    def do_action(self, msg):

        self.validate_data(msg)
        self.read_data()

        ipcmd = ['/usr/sbin/iptables', '-t', 'nat']
        if self.action == "add":
            ipcmdAdd = ['-I', 'VSERVER', '-s', str(self.ip_src) + '/32', '-p', 'tcp', '-m', 'tcp', '--dport',
                        str(self.port_dst), '-j', 'DNAT', '--to-destination',
                 str(self.ip_dst_lan) + ':' + str(self.port_dst_lan)]
            ipcmd = ipcmd + ipcmdAdd
            logger.info("INSERTING: {}".format(str(' '.join(ipcmd[1:]))))
            logger.info("RULE_TIME_OUT: {} minutes".format(self.rule_timeout))
        elif self.action == "del":
            ipcmdAdd = ['-D', 'VSERVER', '-s', str(self.ip_src) + '/32', '-p', 'tcp', '-m', 'tcp', '--dport',
                        str(self.port_dst), '-j', 'DNAT', '--to-destination',
                        str(self.ip_dst_lan) + ':' + str(self.port_dst_lan)]
            ipcmd = ipcmd + ipcmdAdd
            logger.info("DELETING: {}".format(str(' '.join(ipcmd[1:]))))
        elif self.action == "flush":
            ipcmd = ipcmd + ['-F', 'VSERVER']
            logger.info("FLUSHING ALL: {}".format(str(' '.join(ipcmd[1:]))))
        else:
            raise Exception("Invalid action [ {} ]".format(self.action))

        # Only executes the rule at production environment
        if not DEV:
            process = subprocess.Popen(ipcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.communicate()
            if process.returncode != 0:
                logger.error("RULE EXECUTION FAIL: Return Code: {}  STDOUT: {}".format(str(process.returncode), str(process.stdout)))
                return False

        # Shedule task for delete rule if its a new insert
        if self.action == "add":
            ipcmd[3] = '-D'
            logger.debug("Creating Timer task for rule removal, executes in {} minutes".format(str(self.rule_timeout)))
            Timer(float(self.rule_timeout) * 60.0, schedule_delete_rule, [ipcmd]).start()

        return True

def schedule_delete_rule(ipcmd):
    try:
        ipcmd[3] = '-D'
        logger.info("DELETING: {}".format(' '.join(ipcmd[1:])))
        if not DEV:
            process = subprocess.Popen(ipcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.communicate()
            if process.returncode != 0:
                raise Exception("RULE REMOVAL EXECUTION FAIL: Return Code: {} STDOUT: {}".format(str(process.returncode), str(process.stdout)))
    except Exception as e2:
        logger.error(str(e2))


class AESCipher(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


if __name__ == '__main__':

    if len(sys.argv) == 3 and 'prod' == sys.argv[2]:
        DEV = False
        CONFIG_FILE = "config/config_server.json"
        LOGGING_LEVEL = logging.INFO

    try:
        with open(CONFIG_FILE) as json_data_file:
            data = json.load(json_data_file)
        known_srv_ip = data["known_srv_ip"]
        port_srv = data["port_srv"]
        host_srv = data["host_srv"]
        ssl_key_file = data["ssl_key_file"]
        ssl_cert_file = data["ssl_cert_file"]
        log_file = data["log_file"]
        pid_file = data["pid_file"]
        aes_key = data["aes_key"]
        api_key = data["api_key"]
    except KeyError as e:
        raise Exception("Error reading {} config key".format(e))
    except Exception as e:
        print(str(e))
        sys.exit(2)

    if DEV:
        pid_file = str(os.getcwd()) + os.path.sep + pid_file
        ssl_cert_file = str(os.getcwd()) + os.path.sep + ssl_cert_file
        ssl_key_file = str(os.getcwd()) + os.path.sep + ssl_key_file
        log_file = str(os.getcwd()) + os.path.sep + log_file

    logger = logging.getLogger("doorOpenerLog")
    logging.basicConfig(level=LOGGING_LEVEL, filename=log_file, format='[%(levelname)s] - %(asctime)s : %(message)s')
    logger.info("\n==============================================================================================================================================================================")

    server = DaemonServer(pidfile=pid_file,
                          host_srv=host_srv,
                          port_srv=port_srv,
                          known_srv_ip=known_srv_ip,
                          ssl_cert_file=ssl_cert_file,
                          ssl_key_file=ssl_key_file,
                          aes_key=aes_key,
                          api_key=api_key)

    if len(sys.argv) == 2 or len(sys.argv) == 3:
        if 'start' == sys.argv[1]:
            config_print = """
    KNOWN_SRV_IP = {}
    PORT_SRV = {}
    HOST_SRV = {}
    SSL_KEYFILE = {}
    SSL_CERTFILE = {}
    LOG_FILE = {}
    PID_FILE = {}"""
            logger.warning("STARTING doorOpener")
            logger.info("CONFIG FILE : " + CONFIG_FILE)
            logger.info(config_print.format(known_srv_ip, port_srv, host_srv, ssl_key_file, ssl_cert_file, log_file, pid_file))
            server.start()
        elif 'stop' == sys.argv[1]:
            logger.warning("STOPPING doorOpener")
            server.stop()
        elif 'restart' == sys.argv[1]:
            logger.warning("RESTARTING doorOpener")
            server.restart()
        else:
            logger.error("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        logger.warning("usage: %s start|stop|restart" % sys.argv[0])
        sys.exit(2)
