import dpkt
from collections import Counter
from statistics import StatsEntity
from miscnet import rtoq
import cipher

# This class does a lot of heavy lifting with statistics generation
# It acts as a central repository of information for analyzing
# modules to use.

class Conversation:
    def __init__(self, caddr, cport, saddr, sport, csuite):
        # Client address and port
        self.caddr = caddr
        self.cport = cport
        # Server address and port
        self.saddr = saddr
        self.sport = sport
        # Cipher suite - we assume the same cipher suite is in use in both
        # directions because seriously, who doesn't do that? :)
        # Needs to be of type cipher
        self.csuite = csuite
        # Client stats
        self.cstat = StatsEntity()
        # Server stats
        self.sstat = StatsEntity()

    def addPacket(self, ts, eth):
        if type(eth) != dpkt.ethernet.Ethernet:
            raise TypeError("Expected dpkt.ethernet.Ethernet, received " + str(type(p)) + " instead")

        ip = eth.data
        tcp = ip.data
        app = tcp.data

        # Decide if this is a server or client packet
        stat = None
        # client
        if ip.src == self.caddr and tcp.sport == self.cport:
            stat = self.cstat
        # server
        elif ip.src == self.saddr and tcp.sport == self.sport:
            stat = self.sstat
        else:
            raise ValueError("Conversation '" + str(self) + "' received a packet that was not a part of the conversation")

        # Packet counts
        stat.pcount = stat.pcount + 1

        # Packet sizes (of application layer data)
        l = len(app)
        if l in stat.psizes:
            stat.psizes[l] = stat.psizes[l] + 1
        else:
            stat.psizes[l] = 1

        if stat.lasttimestamp == None:
            stat.lasttimestamp = ts
        else:
            # time between packets
            time = ts - stat.lasttimestamp
            if time in stat.timings:
                stat.timings[time] = stat.timings[time] + 1
            else:
                stat.timings[time] = 1
            stat.lasttimestamp = ts

    # Returns the sum of a dictionary where the key
    # is a size or a latency, and the value is the number
    # of occurences of that value
    def sumdict(self, d):
        total = 0
        for value in d.keys():
            total = total + value * d[value]
        return total

    # Returns the average of a dictionary where the key
    # is a size or a latency, and the value is the number
    # of occurences of that value
    def averagedict(self, d):
        return self.sumdict(d) / len(d.keys())


    # Plain old getters
    def clientPacketCount(self):
        return self.cstat.pcount
    def serverPacketCount(self):
        return self.sstat.pcount

    # Length getters
    def clientAverageLength(self):
        return self.averagedict(self.cstat.psizes)
    def serverAverageLength(self):
        return self.averagedict(self.sstat.psizes)

    def clientLengthMode(self, n):
        return Counter(self.cstat.psizes).most_common(n)
    def serverLengthMode(self, n):
        return Counter(self.sstat.psizes).most_common(n)

    def clientTotalLength(self):
        return self.sumdict(self.cstat.psizes)
    def serverTotalLength(self):
        return self.sumdict(self.sstat.psizes)

    def clientLengths(self):
        return self.cstat.psizes
    def serverLengths(self):
        return self.sstat.psizes

    # Timing getters
    def clientAverageTime(self):
        return self.averagedict(self.cstat.timings)
    def serverAverageTime(self):
        return self.averagedict(self.sstat.timings)

    def clientTotalTime(self):
        return self.sumdict(self.cstat.timings)
    def serverTotalTime(self):
        return self.sumdict(self.sstat.timings)

    def clientTimingMode(self, n):
        return Counter(self.cstat.timings).most_common(n)
    def serverTimingMode(self, n):
        return Counter(self.sstat.timings).most_common(n)

    def clientTimings(self):
        return self.cstat.timings
    def serverTimings(self):
        return self.sstat.timings

    # Just return the ciphersuite method, woohoo method chaining
    def ciphersuite(self):
        return self.csuite

    def __str__(self):
        return "%s:%s -> %s:%s" % (rtoq(self.caddr), self.cport, rtoq(self.saddr), self.sport)
