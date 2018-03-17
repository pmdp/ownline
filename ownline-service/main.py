#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

from ownline_service import service, logger, config_name, config
import sys


if __name__ == '__main__':
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            logger.info("STARTING ownline-service")
            logger.info("CONFIG NAME = {}".format(config_name))
            config_print = """
    KNOWN_SRV_IP = {}
    PORT_SRV = {}
    HOST_SRV = {}
    SSL_KEYFILE = {}
    SSL_CERTFILE = {}"""
            logger.info(config_print.format(config.KNOWN_SRV_IP, config.PORT_SRV, config.HOST_SRV, config.SSL_KEY_FILE,
                                            config.SSL_CERT_FILE))
            if config.DEBUG and config_name == 'development':
                # If debugging not create a daemon, just run the service
                logger.info("Debugging mode")
                service.run()
            elif config.DEBUG and config_name == 'production':
                production_print = """
    PID_FILE = {}
    LOG_FILE = {}
                """
                logger.info(production_print.format(config.PID_FILE, config.LOG_FILE))
                # Start daemon at production
                logger.info("Daemon mode")
                service.start()
        elif 'stop' == sys.argv[1]:
            logger.warning("STOPPING ownline-service")
            service.stop()
        elif 'restart' == sys.argv[1]:
            logger.warning("RESTARTING ownline-service")
            service.restart()
        else:
            logger.error("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        logger.warning("usage: {} start|stop|restart".format(sys.argv[0]))
        sys.exit(2)
