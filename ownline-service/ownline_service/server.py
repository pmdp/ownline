from socketserver import TCPServer, StreamRequestHandler
from threading import current_thread
import ssl
import logging
import queue


class OwnlineServer(TCPServer):
    """
    OwnlineServer is a TCP server that listens on a SSL/TLS socket connection for encrypted AES message only
    from well known server known_srv_ip
    When a message comes, put it at a queue and waits until a response for the client
    """

    def __init__(self, addr_port, request_handler, ssl_key_file=None, ssl_cert_file=None, known_srv_ip=None):
        super().__init__(addr_port, request_handler)
        self.keyfile = ssl_key_file
        self.certfile = ssl_cert_file
        self.ssl_version = ssl.PROTOCOL_TLSv1_2
        self.known_srv_ip = known_srv_ip
        self.logger = logging.getLogger("ownline_service_log")

    def get_request(self):
        conn, addr = self.socket.accept()
        ssl_conn = ssl.wrap_socket(conn, keyfile=self.keyfile, certfile=self.certfile,
                                   ssl_version=self.ssl_version,
                                   cert_reqs=ssl.CERT_NONE, server_side=True,)
        self.logger.debug("SSLSocket peername: {}".format(repr(ssl_conn.getpeername())))
        self.logger.debug("SSLSocket cipher: {}".format(ssl_conn.cipher()))
        self.logger.debug("SSLSocket ssl version: {}".format(ssl_conn.ssl_version))
        self.logger.info("Accepted connection from {}".format(str(addr)))
        return ssl_conn, addr

    def verify_request(self, request, client_address):
        #todo: validate SSL connection
        # Called automatically, if return true continue with the request
        if str(client_address[0]) != self.known_srv_ip:
            self.logger.error("Connection comes from untrusted ip: {}".format(str(client_address[0])))
            return False
        return True

# factory method for handler
def get_ownline_server_handler(message_received_queue):
    class OwnlineServerHandler(StreamRequestHandler):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def handle(self):
            raw = self.rfile.readline().decode().strip()
            response_queue = queue.Queue()
            message = {"cipher_message": raw, "response_queue": response_queue}
            message_received_queue.put(message)
            # Wait until response
            response = response_queue.get(block=True, timeout=None)
            self.wfile.write(response)

    return OwnlineServerHandler
