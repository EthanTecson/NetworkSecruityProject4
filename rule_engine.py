class Rule:
    def __init__(self, action, protocol, src, dst, dport):
        self.action = action
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.dport = dport

    def matches(self, packet):
        
        if self.protocol != packet["protocol"]: 
            return False 
        if self.src != "ANY" and self.src != packet["src_ip"]:
            return False
        if self.dport != "ANY" and self.dport != packet["dst_port"]:
            return False
        if self.dst != "ANY" and self.dst != packet["dst_ip"]:
            return False

        return True 


"""
This is what oversees the entire rule table and usees matches() to actaully check if each 
each row of the table is correct
"""
class RuleEngine:
    def __init__(self, rules):
        self.rules = rules

    def match(self, packet):

        for rule in self.rules:
            if rule.matches(packet):
                return rule.action

        return "DROP"
