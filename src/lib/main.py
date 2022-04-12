from syl.syl import SylSSLSocket
from syl.enums import SylSSLCipherSuites

from user import SylUser

class SylChatConnection(object):
    verified = False

    def __init__(self, ignore_security_errors=False, cipher_suite=SylSSLCipherSuites.X448_WITH_AES_AND_SHA3):
        assert isinstance(cipher_suite, SylSSLCipherSuites)

        self.cipher_suite = cipher_suite
        self.wrapped_socket = SylSSLSocket(cipher_suite=cipher_suite, ignore_security_errors=ignore_security_errors)
    
    def __del__(self):
        self.close()

    def close(self):
        self.wrapped_socket.close()

    def connect(self, address):
        return self.wrapped_socket.connect(address)
    
    def verify_connect(self):
        self.wrapped_socket.verify_connect()
        assert self.wrapped_socket.recv(5) == b"SYLC\n"

        return SylUser(self.wrapped_socket)