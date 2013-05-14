import re
import dpkt
import sys
import os
from miscnet import rtoq
from cipher import Ciphersuite
from conversation import Conversation

class HandshakeScanner:
    def __init__(self):
        # This will let the scanner instance keep track
        # of partially-open handshakes
        self.handshakes = {}

    # This function assumes that this is a TCP/IP packet.
    # The main function should check this.
    def checkPacket(self, ip):
        # All we require is that we get Ethernet frames
        if type(ip) != dpkt.ip.IP:
            raise TypeError("Expected dpkt.ip.IP, received " + str(type(ip)) + " instead")

        tcp = ip.data

        # Here be dragons

        # The SSH server sends its version number before the client does. Because
        # we want to index the handshakes dictionary by (clientaddr, clientport, serveraddr, serverport)
        # (which is totally arbitrary), we build an 'index tuple' and the reverse of it, to detect
        # the client responding to the server
        index_tuple =   ip.dst, tcp.dport, ip.src, tcp.sport
        reverse_tuple = ip.src, tcp.sport, ip.dst, tcp.dport
        # If we see evidence of an SSH handshake
        if re.search('^SSH-2.0-', str(tcp.data)):
            # If this is the first SSH packet we have seen (from this pair of hosts+ports),
            # this will be the server sending its version number to the client (tcp connection
            # is already established at this point)
            # TODO check if TCP Fast Open affects the SSH handshake ordering (suspecting no)

            # This is true when the client sends its version number to the server, after
            # the server has sent its own version number
            if (reverse_tuple in self.handshakes) and type(self.handshakes[reverse_tuple]) == bool and self.handshakes[reverse_tuple] == False:
                self.handshakes[reverse_tuple] = True
                # Returns a Conversation object.
                # Right now, we don't detect the ciphersuite,
                # we just assume that the ciphersuite is "aes128-ctr hmac-md5 none"
                return Conversation(ip.src, tcp.sport, ip.dst, tcp.dport, Ciphersuite("aes128-ctr", "hmac-md5", False))

            # This is less specific, so it needs to come after the reverse_tuple check
            # When the client responds, the index_tuple will never be in self.handshakes -
            # only the reverse_tuple will be (because the server sends its version first)
            if index_tuple not in self.handshakes:
                # This will get changed to 'True' when the client responds
                self.handshakes[index_tuple] = False
                return None
        else:
            return None

    def getHandshakes(self):
        return self.handshakes
