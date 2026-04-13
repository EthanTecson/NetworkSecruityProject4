import json
from solution.firewall import Firewall
from solution.rule_engine import Rule, RuleEngine

# Firewall rules: first match wins
rules = [
    Rule("ALLOW", "TCP", "10.0.0.0/24", "ANY", 80),
    Rule("DROP", "TCP", "ANY", "ANY", 23),
    Rule("LOG", "ALL", "ANY", "ANY", "ANY"),
]

fw = Firewall(RuleEngine(rules))

with open("packets.json") as f:
    packets = json.load(f)

# Process packets one by one from the input stream

for pkt in packets:
    result = fw.process_packet(pkt)
    print(result)
