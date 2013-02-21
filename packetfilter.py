import dpkt
import conversation

class PacketFilter:
    def __init__(self):
        # This will become a dictionary indexed by
        # (caddr, cport, saddr, sport) tuples with
        # keys that are Conversation objects
        self.conversations = {}

    def addConversation(self, c):
        self.conversations[c.caddr, c.cport, c.saddr, c.sport] = c

    # This function assumes all packets are TCP/IP
    # The "main" function should have checked this
    # This function sorts Ethernet frames into
    # Conversations
    # Does nothing with packets that are not part of
    # a Conversation
    def filterPacket(self, ts, eth):
        if type(eth) != dpkt.ethernet.Ethernet:
            raise TypeError("Expected dpkt.ethernet.Ethernet, received " + str(type(eth)) + " instead")
        ip = eth.data
        tcp = ip.data

        # We check one (or both) of these against the lookup table
        # 'conversations' and add the packet to the conversation
        tuples = [ (ip.src, tcp.sport, ip.dst, tcp.dport), (ip.dst, tcp.dport, ip.src, tcp.sport) ]
        for t in tuples:
            if t in self.conversations:
                c = self.conversations[t]
                c.addPacket(ts, eth)
                break

    def getConversations(self):
        return self.conversations.values()
