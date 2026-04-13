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
        if self.state_table.is_established(packet):
            return "ALLOW"

        if self.state_table.is_suspicious(packet):
            self.logs.append({"packet": packet, "reason": "Suspicious TCP behavior"})
            logging.info({"packet": packet, "reason": "Suspicious TCP behavior"})
            return "LOG"

        action = self.rule_engine.match(packet)

        if action == "LOG":
            self.logs.append({"packet": packet, "reason": "Matched LOG rule"})
            logging.info({"packet": packet, "reason": "Matched LOG rule"})

        if packet["protocol"] == "TCP":
            self.state_table.update(packet, action)

        return action
