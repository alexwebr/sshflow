#!/usr/bin/python2.7
import dpkt
import sys
import re
import os

# Written by us
from conversation import Conversation
from handshake import HandshakeScanner
from packetfilter import PacketFilter

print "| sshflow"

# Main!
if len(sys.argv) != 2:
    print "error: you must specify a single PCAP file on the command line"
    exit(1)

try:
    f = open(sys.argv[1], 'rb')
except IOError:
    print "error: couldn't open the file '%s'" % (sys.argv[1])
    exit(1)

try:
    pcap = dpkt.pcap.Reader(f)
except ValueError:
    print "error: file couldn't be parsed by dpkt. if exporting from wireshark, use 'Wireshark/tcpdump/... - libpcap' file type"
    exit(1)


print "loading analyzers"
# Modify python's path to look for modules in the 'analyzers' subdirectory
# Probably an enormous hack.
sys.path.append(sys.path[0] + "/analyzers")
analyzers = []
for fname in os.listdir(sys.path[0] + "/analyzers"):
    # We only want to load modules with a .py extension
    if not re.search("\.py$", fname):
        continue
    name = os.path.splitext(fname)[0]
    print "  " + name
    analyzers.append(__import__(name))


print "generating statistics from pcap file, please wait..."

hs = HandshakeScanner()
filt = PacketFilter()
# Number of packets processed
pcount = 0
for ts, buf in pcap:
    pcount = pcount + 1

    # Parse the Ethernet frame
    # If the packet is not TCP/IP, we just
    # skip over it
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except dpkt.dpkt.UnpackError:
        continue

    if type(eth.data) != dpkt.ip.IP:
        continue
    ip = eth.data
    if type(ip.data) != dpkt.tcp.TCP:
        continue
    tcp = ip.data
    # empty messages are usually ACKS. These are,
    # as far as I can tell, not very useful for
    # statistics
    if len(tcp.data) == 0:
        continue

    # Tuple of (clientaddr, clientport, serveraddr, serverport, Ciphersuite)
    conv = hs.checkPacket(ip)
    if conv != None:
        print "  SSH handshake: " + str(conv)
        filt.addConversation(conv)
    # Else, because if it's a handshake packet we don't care about
    # it for statistics.
    else:
        filt.filterPacket(ts, eth)

print ""

if len(filt.getConversations()) == 0:
    print "processed " + str(pcount) + " packets, no SSH handshakes found"
    exit(2)
else:
  print "processed " + str(pcount) + " packets, analysis follows..."

# Main analysis loop
for c in filt.getConversations():
    print
    print "--- analysis of conversation: " + str(c) + " ---"
    for a in analyzers:
        a.analyze(c)

print "--- end of analyses ---"
