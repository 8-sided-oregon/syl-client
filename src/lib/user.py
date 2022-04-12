from functools import total_ordering
from cryptography.hazmat.primitives.asymmetric.ed448 import *
from cryptography.hazmat.primitives.asymmetric.x448 import *
from cryptography.hazmat.primitives import serialization
from syl.syl import SylSSLSocket

from helper import *
from errors import *

import json

class SylUser(object):
    def __init__(self, priv_key: Ed448PrivateKey, user_id):
        self.priv_key = priv_key
        self.pub_key = self.priv_key.public_key()
        self.user_id = user_id
    
    def sign(self, bytes):
        return self.priv_key.sign(bytes)
    
    def verify(self, bytes):
        return self.pub_key.verify(bytes)

class SylUserConnection(object):
    def __init__(self, socket_wrapper: SylSSLSocket):
        self.wrapped_socket = socket_wrapper

    def _recv_command_response(self):
        output, total_recved, binary = None, "", []
        while not match_status_code(output):
            if output != None or output.startswith("0: "):
                total_recved += output[3:]

            if output == "BINDAT":
                binary.append(recv_lookahead(self.wrapped_socket))

            output = recv_until_nl(self.wrapped_socket).decode()
        
        status = output

        return (status, total_recved, binary)

    def _send_command(self, command, *args):
        self.wrapped_socket.send(command.upper().encode("utf-8"))
        
        for arg in args:
            self.wrapped_socket.send(b" " + str(arg).encode("utf-8"))
        
        return self._recv_command_response()
    
    def _send_binary(self, data):
        self.wrapped_socket(b"BINARY DATA\n")

        send_lookahead(self.wrapped_socket, data)

        return self._recv_command_response()

    def login(self, private_key: Ed448PrivateKey, user_id):
        _, _, challenge = self._send_command("LOGIN", user_id)
        assert len(challenge) == 1

        private_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
        )
        x448_key = X448PrivateKey.from_private_bytes(private_bytes)
        _, _, status = self._send_binary(x448_key.exchange(challenge))
        if not status.startswith(b"200"):
            raise InvalidCredentialsError()

        self.user = SylUser(private_key, user_id)

        return status

    def get_self_pub_key(self):
        return self.user.pub_key
    
    def get_self_user_id(self):
        return self.user.user_id

    def get_user_pub_key(self, user_id):
        status, _, pub_key = self._send_command("PUBKU", user_id)
        if not status.startswith(b"200") or pub_key != None:
            raise InvalidUserError()
        
        return pub_key

    def get_backlogged_messages(self):
        raise NotImplementedError()
    
    def get_messenger(self):
        SylUserChatSession(self)

class SylUserChatSession(object):
    def __init__(self, connection):
        self.wrapped_connection = connection

    def get_message_sender(self):
        None
    
    def get_message_reciever(self):
        None

    def get_multimedia_sender(self):
        None

    def get_multimedia_reciever(self):
        None