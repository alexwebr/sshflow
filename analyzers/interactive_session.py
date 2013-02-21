# Tries to determine if an SSH conversation is an interactive
# session or not

import conversation
import cipher

def analyze(c):
    clm = c.clientLengthMode(1)[0][0]
    slm = c.serverLengthMode(1)[0][0]
    smallest = c.ciphersuite().smallestPacket()
    if slm == smallest and clm == smallest:
      print
      print "-> Likely an interactive shell session"
