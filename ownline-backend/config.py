import os
import datetime

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    # Flask general
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'very-secret-thing'

    # Telegram
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN') or 'null'
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID') or 'null'

    # JWT
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=os.environ.get('JWT_ACCESS_TOKEN_TIME_DELTA')) \
        if os.environ.get('JWT_ACCESS_TOKEN_TIME_DELTA') else datetime.timedelta(minutes=60)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(minutes=os.environ.get('JWT_REFRESH_TOKEN_TIME_DELTA')) \
        if os.environ.get('JWT_REFRESH_TOKEN_TIME_DELTA') else datetime.timedelta(days=10)
    JWT_TOKEN_LOCATION = 'headers' #['headers', 'cookies']
    JWT_ALGORITHM = 'HS512'
    JWT_HEADER_TYPE = ''

    # API
    OWNLINE_SERVICE_HOST_NAME_DST = os.environ.get('OWNLINE_SERVICE_ENDPOINT') or '127.0.0.1'
    OWNLINE_SERVICE_PORT_DST = os.environ.get('OWNLINE_SERVICE_PORT') or 9999
    OWNLINE_AES_KEY = os.environ.get('OWNLINE_AES_KEY') or 'zzzzzzzzzzzzzzzzzzzzzzzzzzz'
    OWNLINE_SSL_CERT_FILE =os.environ.get('OWNLINE_SSL_CERT_FILE') or 'ssl_cert/server.crt'

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or os.path.join(basedir, 'db-test.json')


class TestingConfig(Config):
    TESTING = True
    DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'test-db.json'
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DATABASE_URI = os.environ.get('DATABASE_URL') or os.path.join(basedir, 'db.json')

    # JWT
    JWT_COOKIE_SECURE = True

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)


class DockerConfig(ProductionConfig):
    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)

        # log to stderr
        import logging
        from logging import StreamHandler
        file_handler = StreamHandler()
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)


class UnixConfig(ProductionConfig):
    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)

        # log to syslog
        import logging
        from logging.handlers import SysLogHandler
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.INFO)
        app.logger.addHandler(syslog_handler)


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'unix': UnixConfig,
    'default': DevelopmentConfig
}