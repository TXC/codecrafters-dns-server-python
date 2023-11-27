import enum
import struct
from dataclasses import dataclass


class QClass(enum.Enum):
    #: the Internet
    IN = 1

    #: the CSNET class (Obsolete - used only for examples in some
    #: obsolete RFCs)
    CS = 2

    #: the CHAOS class
    CH = 3

    #: Hesiod [Dyer 87]
    HS = 4


class QType(enum.Enum):
    # a host address
    A = 1

    # an authoritative name server
    NS = 2

    # a mail destination (Obsolete - use MX)
    MD = 3

    # a mail forwarder (Obsolete - use MX)
    MF = 4

    # the canonical name for an alias
    CNAME = 5

    # marks the start of a zone of authority
    SOA = 6

    # a mailbox domain name (EXPERIMENTAL)
    MB = 7

    # a mail group member (EXPERIMENTAL)
    MG = 8

    # a mail rename domain name (EXPERIMENTAL)
    MR = 9

    # a null RR (EXPERIMENTAL)
    NULL = 10

    # a well known service description
    WKS = 11

    # a domain name pointer
    PTR = 12

    # host information
    HINFO = 13

    # mailbox or mail list information
    MINFO = 14

    # mail exchange
    MX = 15

    # text strings
    TXT = 16


@dataclass
class Question:
    qname: str
    qtype: QType = QType.A
    qclass: QClass = QClass.IN

    def serialize(self) -> bytes:
        res = b''
        res = (
            res + self.encode(self.qname)
            + struct.pack('>HH', self.qtype.value, self.qclass.value)
        )

        return res

    @staticmethod
    def encode(name: str) -> bytes:
        res = b''
        parts = name.split('.')
        for part in parts:
            ascii_part = part.encode('ascii')
            res = res + len(ascii_part).to_bytes(1, 'big') + ascii_part

        res = res + b'\x00'
        return res

    @classmethod
    def from_bytes(self, data: bytes) -> "Question":
        i = 0
        qname = ''
        while i < len(data):
            if data[i] == 0x00:
                break

            length = int.from_bytes(data[i:i+1], 'big')
            i += 1
            qname += data[i:i + length].decode('utf-8') + '.'
            i += length

        qtype = int.from_bytes(data[i:i + 2], 'big')
        qclass = int.from_bytes(data[i + 3: i + 5], 'big')

        if qname[-1] == '.':
            qname = qname[0:-1]

        return self(
            qname=qname,
            qtype=QType(qtype),
            qclass=QClass(qclass)
        )
