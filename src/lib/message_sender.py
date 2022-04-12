from cryptography.hazmat.primitives.asymmetric.ed448 import *
from cryptography.hazmat.primitives.asymmetric.x448 import *
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.hashes import Hash, SHA3_256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from syl.syl import SylSSLSocket

from user import SylUserConnection
from helper import *

import os

class KeyPair(object):
    def _gen_sym(self, key, salt=None):
        self.sym_key = HKDF(
            algorithm=SHA3_256,
            length=32,
            salt=salt,
            info=b"data lol"
        ).derive(key)

    def _gen_mac(self, key, salt=None):
        self.mac_key = HKDF(
            algorithm=SHA3_256,
            length=32,
            salt=salt,
            info=b"mac key"
        ).derive(key)

    def exchange(self, pk, peer_pb):
        shared_key = pk.exchange(peer_pb)
        self._gen_sym(shared_key)
        self._gen_mac(shared_key)

    def reexchange_hash(self):
        self._gen_sym(self.sym_key)
        self._gen_mac(self.mac_key)
    
    def mix_dh(self, pk, pb):
        shared_key = pk.exchange(pb)

        self._gen_sym(self.mac_key, shared_key)
        self._gen_mac(self.sym_key, shared_key)
    
    def get_checksum(self):
        check = Hash(SHA3_256)
        check.update(b"OwO UwU")
        for key in (self.sym_key, self.mac_key):
            check.update(key)
        return check.finalize()

class Message(object):
    data = b""

    def __init__(self, msg_type, keypair):
        self.msg_type = msg_type
        self.keypair = keypair
    
    def add_data(self, data):
        self.data += data
    
    def finalize(self):
        nonce = os.urandom(16)
        encryptor = Cipher(AES(self.keypair.sym_key), modes.CTR(nonce)).encryptor()
        
        encrypted_data = encryptor.update(self.data) + encryptor.finalize()

        message_algo = Hash(SHA3_256())
        message_algo.update(self.keypair.mac_key)
        message_algo.update(encrypted_data)

class SylMessageSender(object):
    exchanged = False

    def __init__(self, connection: SylUserConnection, user_id, keypair=KeyPair()):
        self.wrapped_connection = connection
        self.key_pair = keypair
        self.user_id = user_id
    
    def exchange_keys(self):
        priv_key = self.wrapped_connection.user.priv_key

        private_bytes = priv_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
        )
        x448_key = X448PrivateKey.from_private_bytes(private_bytes)

        public_bytes = x448_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        status, _, _ = self.wrapped_connection._send_command("EX448")
        assert status.startswith("200")
        send_lookahead(self.wrapped_connection.wrapped_socket, public_bytes)
        user_pub_bytes = recv_lookahead(self.wrapped_connection.wrapped_socket)
        user_pub_key = X448PublicKey.from_public_bytes(user_pub_bytes)

        self.key_pair.exchange(x448_key, user_pub_key)
        send_lookahead(self.key_pair.get_checksum())

        self.exchanged = True

        return user_pub_key
    
    def send(self, message, user_id):
        assert self.exchanged

        status, _, _ = self.wrapped_connection._send_command("SMSG", user_id)

        if status.startswith("200"):
            self.wrapped_connection._send_binary()
        else:
            raise RuntimeError("User is offline, and have not previously negotiated keys.")