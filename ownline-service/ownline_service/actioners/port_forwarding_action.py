from ownline_service.actioners.abstract_action import AbstractAction


class PortForwardingAction(AbstractAction):
    """
    Class that executes iptables command to permit connections to LAN devices from a specific ip.
    Makes a new rule in the NAT table of the router to forward a port to a internal private ip
    Needs:
        - ip_src: the authorized IP from the connection will come
        - port_dst: the router port that will be forwarded to LAN
        - ip_dst_lan: internal LAN device ip
        - action: add or del a rule, flush all rules
    Optional:
        - duration: amount of time the NAT rule will be applied (default: 5 minutes)
        - port_dst_lan: internal LAN device port (default: same than port_dst)

    Command :
        iptables -t nat -I PREROUTING -s <ip_source>/32 -p tcp -m tcp --dport <port_src> -j DNAT --to-destination <ip_dst>:<port_dst>

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_add(self, add_request):
        # todo: if check_status in service, ping or http 200 check depending of service type
        ip_src = str(add_request['ip_src'] + '/32')
        port_dst = self.get_free_random_port()
        ip_dst_lan = add_request['service']['ip_dst_lan']
        port_dst_lan = add_request['service']['port_dst_lan']
        dst_lan = str(ip_dst_lan) + ':' + str(port_dst_lan)

        #todo: VSERVER or PREROUTING chains, get from config
        cmd = ['/usr/sbin/iptables', '-t', 'nat', '-I', 'VSERVER', '-s', ip_src, '-p', 'tcp', '-m', 'tcp',
               '--dport', str(port_dst), '-j', 'DNAT', '--to-destination', dst_lan]

        self.logger.info("Inserting port forwarding rule: {}".format(cmd))

        ok, err, out = self.execute_command(cmd)

        if ok:
            self.logger.info("Successful execution")
            session_id = self.get_new_session_id()
            end_timestamp = self.calculate_end_timestamp(add_request['duration'])
            session = {'session_id': session_id,
                       'port_dst': port_dst,
                       'ip_src': ip_src,
                       'ip_dst_lan': ip_dst_lan,
                       'port_dst_lan': port_dst_lan,
                       'end_timestamp': end_timestamp,
                       'proxy': False,
                       'service_public_id': add_request['service']['public_id']}
            response = {'status': 'OK',
                        'session_id': session_id,
                        'port_dst': port_dst,
                        'end_timestamp': end_timestamp,
                        'duration': add_request['duration'],
                        'type': add_request['service']['type']}
            return session, response
        else:
            self.logger.error("Failed execution: stderr: {} stout: {}".format(err, out))
            return False, {'status': 'FAIL'}

    def do_del(self, session):
        ip_src = str(session['ip_src'] + '/32')
        port_dst = str(session['port_dst'])
        ip_dst_lan = session['ip_dst_lan']
        port_dst_lan = session['port_dst_lan']
        dst_lan = str(ip_dst_lan) + ':' + str(port_dst_lan)

        # todo: VSERVER or PREROUTING chains, get from config
        cmd = ['/usr/sbin/iptables', '-t', 'nat', '-D', 'VSERVER', '-s', ip_src, '-p', 'tcp', '-m', 'tcp',
               '--dport', str(port_dst), '-j', 'DNAT', '--to-destination', dst_lan]

        self.logger.info("Deleteing port forwarding rule: {}".format(cmd))

        ok, err, out = self.execute_command(cmd)

        if ok:
            self.logger.info("Successful execution")
            return True, {'status': 'OK'}
        else:
            self.logger.error("Failed execution: stderr: {} stout: {}".format(err, out))
            return False, {'status': 'FAIL'}

    def do_flush(self):
        self.logger.debug("Hi from do_flush at PortForwardingAction class")
        pass




