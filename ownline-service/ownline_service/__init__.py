import logging
import os
from ownline_service.service import OwnlineService
from config import configuration

# Loads configuration by environment
config_name = os.environ.get('CONFIG_NAME') or 'development'

config = configuration[config_name]

logger = logging.getLogger("ownline_service_log")
logging.basicConfig(level=config.LOGGING_LEVEL, format='%(levelname)-5s - %(asctime)s - %(threadName)-13s - %(module)s : %(message)s')
# Set file logging if production
if not config.DEBUG:
    logging.basicConfig(filename=config.LOG_FILE)
logger.info("\n==============================================================================================================================================================================")

service = OwnlineService(config=config, pidfile=config.PID_FILE)
