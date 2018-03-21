from ownline_service.actioners.abstract_action import AbstractAction
import os

SERVER_TEMPLATE = """
server {
    listen {{port_dst}} ssl http2;

    include /opt/etc/ssl_common.conf;

    location / {
        allow {{ip_src}};
        deny all;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version  1.1;

        proxy_pass http://{{dst_lan}};
    }
}
"""


class ReverseProxyAction(AbstractAction):

    def __init__(self, nginx_config_path=None, nginx_binary=None, nginx_servers_folder=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nginx_config_path = nginx_config_path
        self.nginx_servers_folder = nginx_servers_folder
        self.nginx_binary = nginx_binary

        #todo: check servers.d folder exists in nginx_config_path
        #todo: check

    def do_add(self, add_request):
        # todo: if check_status in service, ping or http 200 check depending of service type
        ip_src = add_request['ip_src']
        port_dst = add_request['service']['port_dst'] if 'port_dst' in add_request['service'].keys() \
            else self.get_free_random_port()
        ip_dst_lan = add_request['service']['ip_dst_lan']
        port_dst_lan = add_request['service']['port_dst_lan']
        dst_lan = str(ip_dst_lan) + ':' + str(port_dst_lan)

        # Create iptables rule permiting nginx reverse proxy access
        cmd = [self.iptables_binary, '-I', 'INPUT', '-s', ip_src + '/32', '-p', 'tcp', '-m', 'tcp',
               '--dport', str(port_dst), '-j', 'ACCEPT']

        self.logger.info("Inserting accept input rule: {}".format(cmd))

        ok, err, out = self.execute_command(cmd)

        if ok:
            self.logger.debug("Successful reverse proxy access firewall rule adding execution")
            session_id = self.get_new_session_id()

            # Create new server config from template
            server_conf = SERVER_TEMPLATE.replace("{{ip_src}}", ip_src + '/32')
            server_conf = server_conf.replace("{{port_dst}}", str(port_dst))
            server_conf = server_conf.replace("{{dst_lan}}", dst_lan)
            self.logger.debug("New server config:\n {}".format(server_conf))

            # Writes file to servers.d folder
            server_session_file_name = self.nginx_config_path + '/' + self.nginx_servers_folder + '/' + session_id + '.conf'
            with open(server_session_file_name, 'w') as config_file:
                config_file.write(server_conf)

            #todo check nginx config with: nginx -t
            # reload nginx
            reload_ok = self.check_and_reload_nginx()
            if reload_ok:
                end_timestamp = self.calculate_end_timestamp(add_request['duration'])
                session = {'session_id': session_id,
                           'port_dst': port_dst,
                           'ip_src': ip_src,
                           'ip_dst_lan': ip_dst_lan,
                           'port_dst_lan': port_dst_lan,
                           'end_timestamp': end_timestamp,
                           'proxy': True,
                           'service_public_id': add_request['service']['public_id']}
                response = {'status': 'OK',
                            'session_id': session_id,
                            'port_dst': port_dst,
                            'end_timestamp': end_timestamp,
                            'duration': add_request['duration'],
                            'type': add_request['service']['type']}
                return session, response
        else:
            raise Exception("Failed reverse proxy access firewall rule adding execution: stderr: {} stout: {}".format(err, out))

    def do_del(self, session):
        ip_src = session['ip_src']
        port_dst = str(session['port_dst'])

        cmd = [self.iptables_binary, '-D', 'INPUT', '-s', ip_src + '/32', '-p', 'tcp', '-m', 'tcp',
               '--dport', str(port_dst), '-j', 'ACCEPT']

        self.logger.info("Deleting reverse proxy access firewall rule: {}".format(cmd))

        ok, err, out = self.execute_command(cmd)

        if ok:
            self.logger.debug("Successful deleting execution")

            # Delete session nginx server config file
            server_session_file_name = self.nginx_config_path + '/' + self.nginx_servers_folder + '/' + session['session_id'] + '.conf'
            os.remove(server_session_file_name)
            self.logger.debug("Successful deleting server config file with name: {}".format(session['session_id'] + '.conf'))
            ok_reload = self.check_and_reload_nginx()
            if ok_reload:
                return True, {'status': 'OK'}
        else:
            raise Exception("Failed deleting execution: stderr: {} stout: {}".format(err, out))

    def do_flush(self):
        #todo: delete all rules for OWNLINE_REVERSE_PROXY chain
        #todo: delete all files inside directory servers.d/*.conf
        #todo: reload config
        return

    def check_and_reload_nginx(self):
        check_config_cmd = [self.nginx_binary, '-t']
        ok, err, out = self.execute_command(check_config_cmd)
        if ok:
            reload_cmd = [self.nginx_binary, '-s', 'reload']
            ok_reload, err_reload, out_reload = self.execute_command(reload_cmd)
            if ok_reload:
                self.logger.debug("Successful check and reload nginx execution")
                return True
            else:
                raise Exception("Failed reloading nginx configuration: stderr: {}, stdout: {}".format(err_reload, out_reload))
        else:
            raise Exception("Failed checking nginx configuration: stderr: {}, stdout: {}".format(err, out))
