import conversation

def analyze(c):
    print "General statistics"
    print "  Detected ciphersuite: " + str(c.ciphersuite())
    print "  Smallest possible packet for ciphersuite: " + str(c.ciphersuite().smallestPacket())
    print "  Packets sent by client: " + str(c.clientPacketCount())
    print "  Packets sent by server: " + str(c.serverPacketCount())
    print "  Average client packet length: " + str(c.clientAverageLength())
    print "  Average server packet length: " + str(c.serverAverageLength())
    print "  Total bytes (of SSH data) sent by client: " + str(c.clientTotalLength())
    print "  Total bytes (of SSH data) sent by server: " + str(c.serverTotalLength())
    print "  Most common client packet size: " + str(c.clientLengthMode(5))
    print "  Most common server packet size: " + str(c.serverLengthMode(5))
    print "  Average time between client packets: " + str(c.clientAverageTime())
    print "  Average time between server packets: " + str(c.serverAverageTime())
