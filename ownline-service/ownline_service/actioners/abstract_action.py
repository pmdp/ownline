import socket
import logging
import subprocess
from contextlib import closing
from abc import ABC, abstractmethod
import uuid
import time


class AbstractAction(ABC):

    def __init__(self, debug=True):
        self.logger = logging.getLogger('ownline_service_log')
        self.debug = debug

    def get_free_random_port(self):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    def execute_command(self, cmd):
        if not self.debug:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode, result.stderr.decode(), result.stdout.decode()
        else:
            return True, "stderr test", "stdout test"

    def get_new_session_id(self):
        return str(uuid.uuid4())

    def calculate_end_timestamp(self, duration):
        return round(time.time() + (duration * 60.0))

    @abstractmethod
    def do_add(self, add_request):
        return

    @abstractmethod
    def do_del(self, del_request):
        return

    @abstractmethod
    def do_flush(self):
        return
