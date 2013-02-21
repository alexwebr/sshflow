# Tries to determine if an SSH session is being used to tunnel
# an X11 application

import conversation
import cipher

def analyze(c):
    # Should both be below 0.05 seconds.
    cat = c.clientAverageTime()
    sat = c.serverAverageTime()

    # Should be smallest packet for ciphersuite
    clm1 = c.clientLengthMode(2)[0][0]
    clm2 = c.clientLengthMode(2)[1][0]

    # These should be 'smallest packet' and 'smallest packet + 16', respectively
    slm1 = c.serverLengthMode(2)[0][0]
    slm2 = c.serverLengthMode(2)[1][0]

    # And... smallest packet
    small = c.ciphersuite().smallestPacket()

    if cat < 0.05 and sat < 0.05 and clm2 == small and slm2 == small and clm1 == small+32 and slm1 == small+16:
      print "-> Detected X11 forwarding"
