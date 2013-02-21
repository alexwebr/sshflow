# Tries to determine if a user is tunneling an X11 application over SSH

import conversation
import cipher

def analyze(c):
    small = c.ciphersuite().smallestPacket()
    if c.serverLengthMode(2)[0][0] == small and c.clientAverageLength() > 1000 and c.clientTotalLength() / c.serverTotalLength() > 5:
        print "-> Likely a file copy using SCP, from client to server"
    if c.clientLengthMode(2)[0][0] == small and c.serverAverageLength() > 1000 and c.serverTotalLength() / c.clientTotalLength() > 5:
        print "-> Likely a file copy using SCP, from server to client"
