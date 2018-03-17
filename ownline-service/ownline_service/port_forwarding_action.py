class PortForwardingAction(object):
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

    def __init__(self):
        pass

    def do_add(self, request, service):
        if request['action'] == 'add':
            pass