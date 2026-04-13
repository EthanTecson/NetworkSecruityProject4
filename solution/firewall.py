from solution.rule_engine import RuleEngine
from solution.state_table import StateTable


import logging
logging.basicConfig(level=logging.INFO)


class Firewall:
    def __init__(self, rules):
        self.rule_engine = rules
        self.state_table = StateTable()
        self.logs = []

    def process_packet(self, packet):
        #if the connection is already established, let it through
        if self.state_table.is_established(packet):
            return "ALLOW"

        action = self.rule_engine.match(packet)

        #log suspicious packets
        if self.state_table.is_suspicious(packet):
            self.logs.append({"packet": packet, "reason": "Suspicious TCP behavior", "action": action})
            logging.info({"packet": packet, "reason": "Suspicious TCP behavior", "action": action})
            #return "LOG" #don't log because the rule set doesn't say log suspicious packets
        
        if action == "DROP": #dropped packets should never make it to the state table
            return action

        if packet["protocol"] == "TCP": #if it's a TCP connection, store it in the state table
            self.state_table.update(packet)

        return action
