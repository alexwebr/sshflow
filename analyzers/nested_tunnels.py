# Tries to determine if an SSH session is a tunnel for another
# ssh session
# In an interactive session (many of the smallest possible packets),
# the smallest packet will be double that of the normal smallest packet

import conversation
import cipher

def analyze(c):
    smallest = c.ciphersuite().smallestPacket()
    clm = c.clientLengthMode(1)[0][0]
    slm = c.serverLengthMode(1)[0][0]

    # Guessing that greater than 4 nested tunnels is unlikely :)
    for layers in [ 2, 3, 4 ]:
        if (clm == layers * smallest) or (slm == layers * smallest):
            print "-> Possibly nested tunnels (%s layers detected)" % layers
