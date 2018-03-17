import socket
import json
import logging
import subprocess
from ownline_service.services_db import ServicesDB


class DoorOpener:
    """
    Class that executes iptables command to permit connections to LAN devices from a specific ip.
    Makes a new rule in the NAT table of the router to forward a port to a internal private ip
    Also checks and validates the message payload and needed data
    Needs:
        - ip_src: the authorized IP from the connection will come
        - port_dst: the router port that will be forwarded to LAN
        - ip_dst_lan: internal LAN device ip
        - action: add or del a rule, flush all rules
        - api_key: client verification
    Optional:
        - duration: amount of time the NAT rule will be applied (default: 5 minutes)
        - port_dst_lan: internal LAN device port (default: same than port_dst)

    Command :
        iptables -t nat -I PREROUTING -s <ip_source>/32 -p tcp -m tcp --dport <port_src> -j DNAT --to-destination <ip_dst>:<port_dst>

    """

    def __init__(self, debug=True, api_key=None):
        self.duration = 5
        self.debug = debug
        self.api_key = api_key

        self.logger = logging.getLogger("ownline_service_log")

    def read_data(self):
        self.action = self.message["action"]
        if self.action == "flush":
            return
        self.ip_src = self.message["ip_src"]
        self.port_dst = self.message["port_dst"]
        self.ip_dst_lan = self.message["ip_dst_lan"]
        self.api_key = self.message["api_key"]

        if "port_dst_lan" in self.message.keys():
            self.port_dst_lan = self.message["port_dst_lan"]
        else:
            self.port_dst_lan = self.port_dst

        if "duration" in self.message.keys():
            self.duration = self.message["duration"]

    def validate_data(self, msg):
        self.message = json.loads(msg)
        self.logger.debug("data : " + str(self.message))

        if self.message["action"] is not None and self.message["action"] == "flush":
            return True

        if self.message["action"] is not None \
                and self.message["ip_src"] is not None \
                and self.message["port_dst"] is not None \
                and self.message["ip_dst_lan"] is not None \
                and self.message["api_key"] is not None:
            pass
        else:
            raise Exception("No all needed data specified")
        try:
            socket.inet_aton(self.message["ip_src"])
        except Exception:
            raise Exception("IP_SOURCE [ {} ] is INVALID".format(str(self.message["ip_src"])))
        try:
            socket.inet_aton(self.message["ip_dst_lan"])
        except Exception:
            raise Exception("IP_DST_LAN [ {} ] is INVALID".format(str(self.message["ip_dst_lan"])))

        if self.message["port_dst"] not in range(1024, 65535):
            raise Exception("PORT_DST [ {} ] is INVALID".format(str(self.message["port_dst"])))

        if self.message["action"] not in ["add", "del"]:
            raise Exception("ACTION [ {} ] is INVALID".format(str(self.message["action"])))

        if self.message["api_key"] != self.api_key:
            raise Exception("API_KEY [ {} ] is INVALID".format(str(self.message["api_key"])))

        if "port_dst_lan" in self.message.keys():
            if self.message["port_dst_lan"] not in range(0, 65535):
                raise Exception("PORT_DST_LAN [ {} ] is INVALID".format(str(self.message["port_dst_lan"])))
        if "duration" in self.message.keys():
            if self.message["duration"] not in range(1, 999):
                raise Exception("TIME [ {} ] is INVALID".format(str(self.message["duration"])))

        return True

    def do_action(self, msg):

        self.validate_data(msg)
        self.read_data()

        ip_cmd = ['/usr/sbin/iptables', '-t', 'nat']
        if self.action == "add":
            ip_cmd_add = ['-I', 'VSERVER', '-s', str(self.ip_src) + '/32', '-p', 'tcp', '-m', 'tcp', '--dport',
                        str(self.port_dst), '-j', 'DNAT', '--to-destination',
                 str(self.ip_dst_lan) + ':' + str(self.port_dst_lan)]
            ip_cmd = ip_cmd + ip_cmd_add
            self.logger.info("INSERTING: {}".format(str(' '.join(ip_cmd[1:]))))
            self.logger.info("RULE_TIME_OUT: {} minutes".format(self.duration))
        elif self.action == "del":
            ip_cmd_add = ['-D', 'VSERVER', '-s', str(self.ip_src) + '/32', '-p', 'tcp', '-m', 'tcp', '--dport',
                        str(self.port_dst), '-j', 'DNAT', '--to-destination',
                        str(self.ip_dst_lan) + ':' + str(self.port_dst_lan)]
            ip_cmd = ip_cmd + ip_cmd_add
            self.logger.info("DELETING: {}".format(str(' '.join(ip_cmd[1:]))))
        elif self.action == "flush":
            ip_cmd = ip_cmd + ['-F', 'VSERVER']
            self.logger.info("FLUSHING ALL: {}".format(str(' '.join(ip_cmd[1:]))))
        else:
            raise Exception("Invalid action [ {} ]".format(self.action))

        # Only executes the rule at production environment
        if not self.debug:
            process = subprocess.Popen(ip_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.communicate()
            if process.returncode != 0:
                self.logger.error("RULE EXECUTION FAIL: Return Code: {}  STDOUT: {}".format(str(process.returncode), str(process.stdout)))
                return False

        # Shedule task for delete rule if its a new insert
        if self.action == "add":
            ip_cmd[3] = '-D'
            self.logger.debug("Creating Timer task for rule removal, executes in {} minutes".format(str(self.duration)))
            #Timer(float(self.duration) * 60.0, schedule_delete_rule, [ip_cmd]).start()

        return True

#todo: not a thread for each schedule, instead a thread that checks every second for terminated sessions
# def schedule_delete_rule(ip_cmd):
#     logger = logging.getLogger("ownline_service_log")
#     try:
#         ip_cmd[3] = '-D'
#         logger.info("DELETING: {}".format(' '.join(ip_cmd[1:])))
#         if not config.DEBUG:
#             process = subprocess.Popen(ip_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#             process.communicate()
#             if process.returncode != 0:
#                 raise Exception("RULE REMOVAL EXECUTION FAIL: Return Code: {} STDOUT: {}".format(str(process.returncode), str(process.stdout)))
#     except Exception as e2:
#         logger.error(str(e2))