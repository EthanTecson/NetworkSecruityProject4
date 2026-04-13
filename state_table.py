class StateTable:
    def __init__(self):
        self.connections = set()
        self.tcp_states = {}

    def _key(self, packet):
        return (
            packet["src_ip"],
            packet["src_port"],
            packet["dst_ip"],
            packet["dst_port"],
        )

    def is_established(self, packet):
        # TODO: check forward/reverse flow
        forward = (
            packet["src_ip"],
            packet["src_port"],
            packet["dst_ip"],
            packet["dst_port"],
        )

        backward = (
            packet["dst_ip"],
            packet["dst_port"],
            packet["src_ip"],
            packet["src_port"],
        )

        return forward in self.connections or backward in self.connections

    def update_TCP_connections(self, packet, packet_type):
        packetF = f"{packet['src_ip']} {packet['src_port']} {packet['dst_ip']} {packet['dst_port']}"
        packetB = f"{packet['dst_ip']} {packet['dst_port']} {packet['src_ip']} {packet['src_port']}"
        
        if packetF in self.tcp_states.keys():
            #if self.tcp_states[packetF] == "SYN" and packet_type

        #self.tcp_states[packetF] = 
            pass

    def update(self, packet, action):
        # TODO: implement TCP state tracking
        
        packet_type = ""
        if "SYN" in packet["flags"] and "ACK" in packet["flags"]:
            packet_type = "SYN-ACK"
        elif "SYN" in packet["flags"]:
            packet_type = "SYN"
        elif "ACK" in packet["flags"]:
            packet_type = "ACK"
        
        
    
        if action == "ALLOW" and packet_type == "SYN":
            self.connections.add(self._key(packet))
