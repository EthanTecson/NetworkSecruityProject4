import ipaddress

class Rule:
    def __init__(self, action, protocol, src, dst, dport):
        self.action = action
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.dport = dport

    def _ip_matches(self, rule_ip, packet_ip):
        if rule_ip == "ANY":
            return True
        if "/" in str(rule_ip):
            return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip, strict=False)
        return rule_ip == packet_ip

    def matches(self, packet):
        if self.protocol != "ALL" and self.protocol != packet["protocol"]:
            return False

        if not self._ip_matches(self.src, packet["src_ip"]):
            return False

        if not self._ip_matches(self.dst, packet["dst_ip"]):
            return False

        if self.dport != "ANY" and self.dport != packet["dst_port"]:
            return False

        return True


"""
This manages the full rule list.
It checks rules from top to bottom, and the first matching rule decides the action.
"""
class RuleEngine:
    def __init__(self, rules):
        self.rules = rules

    def match(self, packet):

        for rule in self.rules:
            if rule.matches(packet):
                return rule.action

        return "DROP"
