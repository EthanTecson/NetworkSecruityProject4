class StateTable:
    def __init__(self):
        self.connections = set()

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


    def update(self, packet, action):
        # TODO: implement TCP state tracking
        if action == "ALLOW":
            self.connections.add(self._key(packet))
