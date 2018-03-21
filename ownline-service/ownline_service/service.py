from daemons.prefab import run
from threading import current_thread
import socket
import logging
import time
from ownline_service.aes_cipher import AESCipher
from ownline_service.server import OwnlineServer, get_ownline_server_handler
from ownline_service.services_db import ServicesDB
from ownline_service.actioners.port_forwarding_action import PortForwardingAction
from ownline_service.actioners.reverse_proxy_action import ReverseProxyAction
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
        current_thread().setName("main-thread")
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

        # Actioners
        self.port_forwarding_action = PortForwardingAction(debug=self.debug, iptables_binary=config.IPTABLES_BINARY)
        self.reverse_proxy_action = ReverseProxyAction(debug=self.debug, nginx_config_path=config.NGINX_CONFIG_PATH,
                                                       nginx_servers_folder=config.NGINX_SERVERS_FOLDER,
                                                       nginx_binary=config.NGINX_BINARY,
                                                       iptables_binary=config.IPTABLES_BINARY)

        # Sessions dict
        self.sessions = {}

    def initialize(self):
        try:
            ip_addr = socket.gethostbyname(self.host_srv)
            self.logger.info("Listening on IP = {} - {}  and PORT = {}".format(ip_addr,
                                                                               self.host_srv, str(self.port_srv)))
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
            self.server_thread.setName("server-thread")
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
                    if not self.server and not self.server_thread.is_alive():
                        self.logger.warning("Server is not running")
                        #todo: restart server?
                    # Check for ended sessions for finish them
                    self.check_ended_sessions()
                    # Check for a incoming message (raise Empty exception if no message)
                    queue_object = self.message_received_queue.get(block=False)
                    response = self.do_request(queue_object['cipher_message'])
                    # Adds response to queue, checked in server thread for socket response
                    queue_object['response_queue'].put(response)
                except queue.Empty:
                    pass
                except Exception as e:
                    self.logger.error("{}".format(e))

                time.sleep(self.main_loop_delay)

        self.logger.info("Exiting OwnlineServer")
        #todo: if server still running shutdown and close
        if self.server and self.server_thread.is_alive():
            self.server.shutdown()
            self.server.server_close()
        self.logger.info("Exiting OwnlineService main loop")

    def do_request(self, cipher_message):
        err_msg = False
        response = {'status': 'FAIL'}
        try:
            str_message = self.aes.decrypt(cipher_message)
            self.logger.info("Incoming message: " + str(str_message))
            # Raise exceptions for invalid message
            request = self.validate_and_process_request(str_message)

            if request['action'] == 'flush':
                flush_ok_1 = self.reverse_proxy_action.do_flush()
                flush_ok_2 = self.port_forwarding_action.do_flush()
                if flush_ok_1 and flush_ok_2:
                    response = {'status': 'OK'}
            elif request['action'] == 'add':
                if 'proxy' in request['service'].keys() and request['service']['proxy'] is True:
                    session, response = self.reverse_proxy_action.do_add(request)
                else:
                    session, response = self.port_forwarding_action.do_add(request)
                if session:
                    self.sessions[session['session_id']] = session
            elif request['action'] == 'del':
                if 'proxy' in request['session'].keys() and request['session']['proxy'] is True:
                    status, response = self.reverse_proxy_action.do_del(request['session'])
                else:
                    status, response = self.port_forwarding_action.do_del(request['session'])
                if status:
                    self.logger.info("Deleting session with id: {}".format(request['session']['session_id']))
                    del self.sessions[request['session']['session_id']]
        except json.JSONDecodeError as e1:
            err_msg = "Invalid JSON: {}".format(e1)
        except KeyError as e2:
            err_msg = "{} key not in message".format(e2)
        except ValueError as e3:
            err_msg = "Invalid UUID: {}".format(e3)
        except Exception as e4:
            err_msg = "{}".format(e4)
        finally:
            if err_msg:
                self.logger.error("Error doing request, reason: {}".format(err_msg))
            self.logger.info("Responding with: {}".format(response))
            return self.aes.encrypt(json.dumps(response, separators=(',', ':')))

    def validate_and_process_request(self, str_message):
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
            service = self.services_db.get_service(message['service_public_id'])
            if not service:
                raise Exception("Service with id: {} not exists".format(message['service_public_id']))
            if self.check_already_session_for_that_service(message['service_public_id']):
                raise Exception("There is already a session to that service".format(message['service_public_id']))
            valid_message = {'action': 'add',
                             'ip_src': message['ip_src'],
                             'service': service}

            if 'duration' in message.keys():
                if message['duration'] not in range(1, self.max_session_duration):
                    raise Exception("Invalid duration, not in range(1, {}): {}".format(self.max_session_duration,
                                                                                       message['duration']))
                valid_message['duration'] = message['duration']
            else:
                valid_message['duration'] = self.default_session_duration
        elif message['action'] == 'del':
            uuid.UUID(message['session_id'], version=4)
            session = self.sessions[message['session_id']]
            if not session:
                raise Exception("Session with id: {} not exists".format(message['session_id']))
            valid_message = {'action': 'del', 'session': session}

        return valid_message

    def check_ended_sessions(self):
        for key, session in self.sessions.items():
            if time.time() > session['end_timestamp']:
                self.logger.info("Ended session with id: {}".format(key))
                if session['proxy']:
                    status, response = self.reverse_proxy_action.do_del(session)
                else:
                    status, response = self.port_forwarding_action.do_del(session)

                if status:
                    self.logger.info("Deleting session with id: {}".format(key))
                    del self.sessions[key]
                    break

    def check_already_session_for_that_service(self, service_public_id):
        for key, session in self.sessions.items():
            if session['service_public_id'] == service_public_id:
                return True
        return False




