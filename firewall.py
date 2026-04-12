from rule_engine import RuleEngine
from state_table import StateTable

import logging
logging.basicConfig(level=logging.INFO)


class Firewall:
    def __init__(self, rules):
        self.rule_engine = rules
        self.state_table = StateTable()

    def process_packet(self, packet):
        if self.state_table.is_established(packet):
            return "ALLOW"

        action = self.rule_engine.match(packet)
        
        # include logging for LOG packets
        if action == "LOG":
            logging.info(packet)

        if packet["protocol"] == "TCP":
            self.state_table.update(packet, action)

        return action
