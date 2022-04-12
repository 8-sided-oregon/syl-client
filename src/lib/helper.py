import re

def recv_until_nl(sock):
    c = None
    msg = b""

    while c != b"\n":
        c = sock.recv(1)
        msg += c

    return msg[:-1]

def recv_lookahead(sock, lk_size=2):
    lookahead_bytes = sock.recv(lk_size)
    lookahead = int.from_bytes(lookahead_bytes, byteorder="big")

    return sock.recv(lookahead)

def send_lookahead(sock, data, lk_size=2):
    assert (256 ** lk_size) > len(data)

    lookahead_bytes = len(data).to_bytes(lk_size, byteorder="big")
    sock.send(lookahead_bytes)
    sock.send(data)

def match_status_code(line):
    if b"\n" in line or line == None:
        return False

    pattern = re.compile(b"^[0-9]{3} [A-Z]+$")
    match = pattern.match(line)

    return match != None