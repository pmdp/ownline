import os
import logging

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):

    # Daemon config
    PID_FILE = os.environ.get('PID_FILE') or 'ownline_service.pid'
    MAIN_LOOP_DELAY = 0.5

    # Listening socket config
    HOST_SRV = os.environ.get('HOST_SRV') or '0.0.0.0'
    PORT_SRV = int(os.environ.get('PORT_SRV')) if os.environ.get('PORT_SRV') else 9999

    # Security config
    API_KEY = os.environ.get('API_KEY') or '123'
    AES_KEY = os.environ.get('AES_KEY') or '123'
    SSL_KEY_FILE = os.environ.get('SSL_KEY_FILE') or 'ssl_cert/server.key'
    SSL_CERT_FILE = os.environ.get('SSL_CERT_FILE') or 'ssl_cert/server.crt'

    # Known server config
    KNOWN_SRV_IP = os.environ.get('KNOWN_SRV_IP') or '127.0.0.1'

    # Services database
    SERVICES_JSON_DATABASE = os.environ.get('KNOWN_SRV_IP') or 'db/services.json'

    # Default session duration
    DEFAULT_SESSION_DURATION = int(os.environ.get('DEFAULT_SESSION_DURATION')) \
        if os.environ.get('DEFAULT_SESSION_DURATION') else 3

    # Max session duration (default 24h)
    MAX_SESSION_DURATION = int(os.environ.get('MAX_SESSION_DURATION')) \
        if os.environ.get('MAX_SESSION_DURATION') else 1440

    # iptables binary
    IPTABLES_BINARY = os.environ.get('IPTABLES_BINARY') or 'iptables'

    # Port forwarding target chain
    PORT_FORWARDING_CHAIN = os.environ.get('PORT_FORWARDING_CHAIN') or 'PREROUTING'

    # Reverse proxy with nginx
    NGINX_BINARY = os.environ.get('NGINX_BINARY') or 'nginx'
    NGINX_CONFIG_PATH = os.environ.get('NGINX_CONFIG_PATH') or 'nginx_config/dev/'
    NGINX_SERVERS_FOLDER = 'servers.d'



class DevelopmentConfig(Config):
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG


class ProductionConfig(Config):
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
    LOG_FILE = os.environ.get('LOG_FILE') or 'log/ownline_service.log'


configuration = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}
