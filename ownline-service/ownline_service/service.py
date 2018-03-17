from daemons.prefab import run
from threading import current_thread
import socket
import logging
import time
from ownline_service.aes_cipher import AESCipher
from ownline_service.server import OwnlineServer, get_ownline_server_handler
from ownline_service.services_db import ServicesDB
from ownline_service.port_forwarding_action import PortForwardingAction
from ownline_service.reverse_proxy_action import ReverseProxyAction
import threading
import queue
import json
import uuid
import re


class OwnlineService(run.RunDaemon):
    """
    OwnlineService daemon run method that starts a TCP server
    When a message comes, will call the DoorOpener class to validate data and execute the new rule
    """

    def __init__(self, config=None, **kwargs):
        super().__init__(**kwargs)
        current_thread().setName("main")
        self.logger = logging.getLogger("ownline_service_log")

        self.debug = config.DEBUG
        self.host_srv = config.HOST_SRV
        self.port_srv = config.PORT_SRV
        self.known_srv_ip = config.KNOWN_SRV_IP
        self.ssl_cert_file = config.SSL_CERT_FILE
        self.ssl_key_file = config.SSL_KEY_FILE
        self.aes_key = config.AES_KEY
        self.api_key = config.API_KEY
        self.main_loop_delay = config.MAIN_LOOP_DELAY
        self.default_session_duration = config.DEFAULT_SESSION_DURATION
        self.max_session_duration = config.MAX_SESSION_DURATION

        # TCP SSL server
        self.server = None
        self.server_thread = None

        # aes class for decrypt message
        self.aes = AESCipher(self.aes_key)

        self.services_db = ServicesDB(config.SERVICES_JSON_DATABASE)
        self.message_received_queue = queue.Queue()

    def initialize(self):
        try:
            ip_addr = socket.gethostbyname(self.host_srv)
            self.logger.info("Listening on IP = {} - {}  and PORT = {}".format(ip_addr, self.host_srv, str(self.port_srv)))
        except socket.gaierror:
            self.logger.error("Host name could not be resolved")
            return False

        try:
            # Flush all rules at startup
            #self.opener.do_action('{"action":"flush"}')
            #todo: flush all at startup
            pass
        except Exception as e:
            self.logger.error("Failed to flush all rules")
            return False

        try:
            server_handler = get_ownline_server_handler(self.message_received_queue)
            self.server = OwnlineServer(addr_port=(ip_addr, self.port_srv), request_handler=server_handler,
                                        ssl_key_file=self.ssl_key_file, ssl_cert_file=self.ssl_cert_file,
                                        known_srv_ip=self.known_srv_ip)
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.setDaemon(True)
            self.server_thread.setName("server")
            self.server_thread.start()
            self.logger.info("server started, listening in: {}:{}".format(str(self.host_srv), str(self.port_srv)))
            return True
        except Exception as e1:
            self.logger.error("Failed to create server: " + repr(e1))
            return False

    def run(self):
        self.logger.debug('OwnlineService run method started')

        if self.initialize():
            # MAIN INFINITE LOOP
            self.logger.info('STARTING INFINTE LOOP')
            while True:
                try:
                    # todo: check if server still running and all OK
                    # todo: check if there is a session to finish (end_timeout > now)
                    # Check for a incoming message (raise Empty exception if no message)
                    queue_object = self.message_received_queue.get(block=False)
                    response = self.do_request(queue_object['cipher_message'])
                    # Adds response to queue, checked in server thread for socket response
                    queue_object['response_queue'].put(response)
                except queue.Empty:
                    pass
                except KeyError as e1:
                    self.logger.error("{} not in message".format(str(e1)))
                except Exception as e2:
                    self.logger.error("{}".format(repr(e2)))

                time.sleep(self.main_loop_delay)

        self.logger.info("Exiting OwnlineServer")
        #todo: if server still running shutdown and close
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.logger.info("Exiting OwnlineService main loop")

    def do_request(self, cipher_message):
        str_message = self.aes.decrypt(cipher_message)
        self.logger.debug("MESSAGE: " + str(str_message))
        request = self.validate_and_process_request(str_message)
        if request:
            #todo: make magic (nginx + dnat)
            #todo: if http|proxy create iptables rule accepting connection from ip_src to https nginx reverse proxy and add nginx server to configuration
            #todo: if tcp|nat create NAT rule that forwards packets to LAN with DNAT
            #todo: add session to list
            #todo: if check_status in service, ping or http 200 check

            service = self.services_db.get_service(request['service_public_id'])

            if service['type'] == 'tcp':
                actioner = PortForwardingAction()
            elif service['type'] == 'http':
                actioner = ReverseProxyAction()
            return 'OK'
        else:
            return 'FAIL'

    def validate_and_process_request(self, str_message):
        err_msg = False
        try:
            # Raise JSONDecodeError for invalid JSON
            message = json.loads(str_message)

            # First check for valid API_KEY
            if message['api_key'] != self.api_key:
                raise Exception("Invalid api_key: {}".format(message['api_key']))

            # If we are flushing all, no more message validation needed
            if message['action'] == 'flush':
                return {'action': 'flush'}

            if message['action'] not in ('add', 'del'):
                raise Exception("Invalid action: {}".format(message['action']))

            # New dict will be returned
            valid_message = {}

            if message['action'] == 'add':
                regex = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                if not regex.match(message['ip_src']):
                    raise Exception("Invalid ip_src: {}".format(message['ip_src']))
                # Raise ValueError for invalid UUID version 4
                uuid.UUID(message['service_public_id'], version=4)
                if not self.services_db.get_service(message['service_public_id']):
                    raise Exception("Service doesnt exists in DB, id: {}".format(message['service_public_id']))
                valid_message = {'action': 'add',
                                 'ip_src': message['ip_src'],
                                 'service_public_id': message['service_public_id']}
            elif message['action'] == 'del':
                uuid.UUID(message['session_id'], version=4)
                #todo: check if session_id is un session list
                valid_message = {'action': 'del', 'session_id': message['session_id']}
            if 'duration' in message.keys():
                if message['duration'] not in range(1, self.max_session_duration):
                    raise Exception("Invalid duration, not in range(1, {}): {}".format(self.max_session_duration, message['duration']))
                valid_message['duration'] = message['duration']
            else:
                valid_message['duration'] = self.default_session_duration

            return valid_message

        except json.JSONDecodeError as e1:
            err_msg = "Invalid JSON: {}".format(e1)
        except KeyError as e2:
            err_msg = "{} key not in message".format(e2)
        except ValueError as e3:
            err_msg = "Invalid service_public_id UUID: {}".format(e3)
        except Exception as e4:
            err_msg = "{}".format(e4)
        finally:
            if err_msg:
                self.logger.error("Invalid message, cause: {}".format(err_msg))



