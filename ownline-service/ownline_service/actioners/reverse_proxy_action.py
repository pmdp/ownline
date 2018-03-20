from ownline_service.actioners.abstract_action import AbstractAction

class ReverseProxyAction(AbstractAction):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        pass

    def do_add(self, add_request):
        #todo: create iptables rule accepting connection from ip_src to https nginx reverse proxy
        #todo: and add nginx server to configuration
        # todo: if check_status in service, ping or http 200 check depending of service type
        return {}, {}

    def do_del(self, del_request):
        self.logger.debug("Hi from do_del at ReverseProxyAction class")
        return

    def do_flush(self):
        self.logger.debug("Hi from do_flush at ReverseProxyAction class")
        return