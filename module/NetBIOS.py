__author__ = 'root'
import random, socket, time, select
import struct, string, re
import types, errno


class NetBIOS():
    def __init__(self, broadcast=True, listen_port=0):
        self.broadcast = broadcast
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.HEADER_STRUCT_FORMAT = '>HHHHHH'
        self.HEADER_STRUCT_SIZE = struct.calcsize(self.HEADER_STRUCT_FORMAT)
        if self.broadcast:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if listen_port:
            self.sock.bind(( '', listen_port ))

    def write(self, data, ip, port):
        self.sock.sendto(data, ( ip, port ))

    def queryIPForName(self, ip, port=137, timeout=5):
        TYPE_SERVER = 0x20

        trn_id = random.randint(1, 0xFFFF)
        data = self.prepareNetNameQuery(trn_id)
        self.write(data, ip, port)
        ret = self._pollForQueryPacket(trn_id, timeout)
        if ret:
            return map(lambda s: s[0], filter(lambda s: s[1] == TYPE_SERVER, ret))
        else:
            return None
    #
    # Contributed by Jason Anderson
    #
    def _pollForQueryPacket(self, wait_trn_id, timeout):
        end_time = time.time() + timeout
        while True:
            try:
                _timeout = end_time - time.time()
                if _timeout <= 0:
                    return None

                ready, _, _ = select.select([ self.sock.fileno() ], [ ], [ ], _timeout)
                if not ready:
                    return None

                data, _ = self.sock.recvfrom(0xFFFF)
                if len(data) == 0:
                    return None

                trn_id, ret = self.decodeIPQueryPacket(data)

                if trn_id == wait_trn_id:
                    return ret
            except select.error, ex:
                if type(ex) is types.TupleType:
                    if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                        return None
                else:
                    return None

    def prepareNetNameQuery(self, trn_id):
        header = struct.pack(self.HEADER_STRUCT_FORMAT,
                             trn_id, 0x0010, 1, 0, 0, 0)
        payload = self.encode_name('*', 0) + '\x00\x21\x00\x01'

        return header + payload

    def decodeIPQueryPacket(self, data):
        if len(data) < self.HEADER_STRUCT_SIZE:
            return None

        trn_id, code, question_count, answer_count, authority_count, additional_count = struct.unpack(self.HEADER_STRUCT_FORMAT, data[:self.HEADER_STRUCT_SIZE])

        is_response = bool((code >> 15) & 0x01)
        opcode = (code >> 11) & 0x0F
        flags = (code >> 4) & 0x7F
        rcode = code & 0x0F
        numnames = struct.unpack('B', data[self.HEADER_STRUCT_SIZE + 44])[0]

        if numnames > 0:
            ret = [ ]
            offset = self.HEADER_STRUCT_SIZE + 45

            for i in range(0, numnames):
                mynme = data[offset:offset + 15]
                mynme = mynme.strip()
                ret.append(( mynme, ord(data[offset+15]) ))
                offset += 18

            return trn_id, ret
        else:
            return trn_id, None

    def encode_name(self, name, type, scope = None):
        if name == '*':
            name = name + '\0' * 15
        elif len(name) > 15:
            name = name[:15] + chr(type)
        else:
            name = string.ljust(name, 15) + chr(type)

        def _do_first_level_encoding(m):
            s = ord(m.group(0))
            return string.uppercase[s >> 4] + string.uppercase[s & 0x0f]

        encoded_name = chr(len(name) * 2) + re.sub('.', _do_first_level_encoding, name)
        if scope:
            encoded_scope = ''
            for s in string.split(scope, '.'):
                encoded_scope = encoded_scope + chr(len(s)) + s
            return encoded_name + encoded_scope + '\0'
        else:
            return encoded_name + '\0'