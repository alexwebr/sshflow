import socket

# Raw 4-byte address to dotted-quad
def rtoq(buf):
    return socket.inet_ntoa(buf)
