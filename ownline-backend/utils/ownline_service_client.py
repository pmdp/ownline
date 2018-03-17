import socket
import ssl
from utils.AESCipher import AESCipher
from ownline_backend import app
import json


def send(msg):
    try:
        ip_dst = socket.gethostbyname(app.config['OWNLINE_SERVICE_HOST_NAME_DST'])
        if ip_dst is None:
            raise Exception("Different ip_dst and DDNS resolve")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_socket = ssl.wrap_socket(s, ca_certs=app.config['OWNLINE_SSL_CERT_FILE'], cert_reqs=ssl.CERT_NONE,
                                     ssl_version=ssl.PROTOCOL_TLSv1_2)

        try:
            ssl_socket.connect((ip_dst, app.config['OWNLINE_SERVICE_PORT_DST']))
            if app.debug:
                app.logger.debug("SSLSocket peername: {}".format(repr(ssl_socket.getpeername())))
                app.logger.debug("SSLSocket cipher: {}".format(ssl_socket.cipher()))
                app.logger.debug("SSLSocket ssl version: {}".format(ssl_socket.ssl_version))
        except socket.error as e:
            raise Exception("Socket connection error: " + str(e))

        aes = AESCipher(app.config['OWNLINE_AES_KEY'])
        crypt = aes.encrypt(json.dumps(msg, separators=(',', ':'))) + b'\n'
        ssl_socket.sendall(crypt)
        response = ssl_socket.recv().decode()
        #ssl_socket.shutdown(how=socket.SHUT_RDWR)
        #ssl_socket.close()
        return response
    except Exception as e:
        app.logger.error(str(e))
        return False

