#!/usr/bin/python

import socket
import ssl
import sys
import getopt
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import json

DEBUG = True

def send(message, host_name_dst, port_dst, ssl_cert_file, aes_key, debug=False):
    try:
        ip_dst = socket.gethostbyname(host_name_dst)
        if ip_dst == None:
            raise Exception("Different ip_dst and DDNS resolve")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_socket = ssl.wrap_socket(s, ca_certs=ssl_cert_file, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2)

        try:
            ssl_socket.connect((ip_dst, port_dst))
            if debug:
                print("SSLSocket peername: {}".format(repr(ssl_socket.getpeername())))
                print("SSLSocket cipher: {}".format(ssl_socket.cipher()))
                print("SSLSocket ssl version: {}".format(ssl_socket.ssl_version))
        except socket.error as e:
            raise Exception("Socket connection error: " + str(e))

        aes = AESCipher(aes_key)
        crypt = aes.encrypt(json.dumps(message))
        ssl_socket.sendall(crypt)
        response = ssl_socket.recv().decode()
        #ssl_socket.shutdown(how=socket.SHUT_RDWR)
        #ssl_socket.close()
        return response
    except Exception as e:
        print(str(e))
        return False


def command_line(argv):
    debug = True
    CONFIG_FILE = "config/config_client_dev.json"
    message = ''
    try:
        opts, args = getopt.getopt(argv, "hPm:", ["message="])
    except getopt.GetoptError:
        print('client.py [-P] -m <JSON message>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('client.py [--P] -m <JSON message>')
            sys.exit()
        elif opt in ("-P", "--production"):
            debug = False
            CONFIG_FILE = "config/config_client.json"
            print("CONFIG FILE: {}".format(CONFIG_FILE))
        elif opt in ("-m", "--message"):
            try:
                message = json.loads(arg)
            except ValueError as e:
                print("Invalid JSON config file {}".format(str(e)))
                sys.exit(2)
            if message == '':
                print ('client.py [-P] -m <JSON message>')
                sys.exit(2)
    try:
        with open(CONFIG_FILE) as json_data_file:
            data = json.load(json_data_file)
        host_name_dst = data["host_name_dst"]
        port_dst = data["port_dst"]
        ssl_cert_file = data["ssl_cert_file"]
        aes_key = data["aes_key"]
        api_key = data["api_key"]
    except KeyError as e:
        raise Exception("Error reading " + str(e) + " config key")
    except Exception as e:
        print(str(e))
        sys.exit(2)

    config_print = """
    host_name_dst = {}
    port_dst = {}
    ssl_cert_file = {}"""
    print(config_print.format(host_name_dst, port_dst, ssl_cert_file))
    message["api_key"] = api_key
    if debug:
        print(message)
    response = send(message, host_name_dst, port_dst, ssl_cert_file, aes_key, debug)
    if response is not None:
        print(str(response))
    if response == "OK":
        sys.exit(0)
    else:
        sys.exit(2)


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


if __name__ == "__main__":
    command_line(sys.argv[1:])
