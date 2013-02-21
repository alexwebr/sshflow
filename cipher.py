# A list of smallest application-layer packet sizes for various cipher suites

class Ciphersuite:
    def __init__(self, cipher, mac, compression):
        if type(cipher) != str or type(mac) != str or type(compression) != bool:
            raise TypeError("Ciphersuite constructor takes two string arguments and one boolean")
        self.cipher = cipher
        self.mac = mac
        self.compression = compression

    def smallestPacket(self):
        # Assume aes-ctr without compression (it's common!)
        # TODO make this really do something useful
        return 48

    def blockSize(self):
        # Assume aes-ctr without compression (it's common!)
        # TODO make this really do something useful
        return 16

    def __str__(self):
        calgo = None
        if self.compression:
            calgo = "none"
        else:
            calgo = "zlib@openssh.com"

        return self.cipher + " " + self.mac + " " + calgo
