import struct
import logging
import copy
from dataclasses import dataclass, field
from app.dns.common import OpCode, ResponseCode, debug

logger = logging.getLogger(__name__)


class HeaderFlags:
    #: A one bit field that specifies whether this message is a query (0), or a
    #: response (1).
    qr: int

    #: A four bit field that specifies kind of query in this message. This
    #: value is set by the originator of a query and copied into the response.
    opcode: int

    #: Authoritative Answer - this bit is valid in responses, and specifies
    #: that the responding name server is an authority for the domain name in
    #: question section.
    aa: int

    #: TrunCation - specifies that this message was truncated due to length
    #: greater than that permitted on the transmission channel.
    tc: int

    #: Recursion Desired - this bit may be set in a query and is copied into
    #: the response.  If RD is set, it directs the name server to pursue the
    #: query recursively. Recursive query support is optional.
    rd: int

    #: Recursion Available - this be is set or cleared in a response, and
    #: denotes whether recursive query support is available in the name server.
    ra: int

    #: Reserved for future use.  Must be zero in all queries and responses.
    z: int

    #: Response code - this 4 bit field is set as part of responses.
    rcode: int

    def __init__(self, qr: int = 0, opcode: int = 0, aa: int = 0, tc: int = 0,
                 rd: int = 0, ra: int = 0, z: int = 0, rcode: int = 0):
        self.qr: int = qr
        self.opcode: int = opcode
        self.aa: int = aa
        self.tc: int = tc
        self.rd: int = rd
        self.ra: int = ra
        self.z: int = z
        self.rcode: int = rcode

    def __index__(self) -> int:
        return (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | self.rcode
        )

    def __bytes__(self) -> bytes:
        return struct.pack('>H', int(self))

    def __repr__(self) -> str:
        op = OpCode.safe_get_name_by_value(self.opcode)
        rcode = ResponseCode.safe_get_name_by_value(self.rcode)

        m = f'OPC: {op}, status: {rcode}, flags: '

        if self.qr == 1:
            m += ' qr'

        if self.aa == 1:
            m += ' aa'

        if self.tc == 1:
            m += ' tc'

        if self.rd == 1:
            m += ' rd'

        if self.ra == 1:
            m += ' ra'

        if self.z != 0:
            m += ' ZZ'

        return m

    def serialize(self) -> bytes:
        return bytes(self)

    def validate(self) -> ResponseCode:
        if self.z != 0:
            logger.error('Header Z must be 0')
            return ResponseCode.FORMAT_ERROR

        if not OpCode.value_exists(self.opcode):
            logger.error(f'OpCode ({self.opcode}) not supported')
            return ResponseCode.NOT_IMPLEMENTED

        if not ResponseCode.value_exists(self.opcode):
            logger.error(f'Response Code ({self.rcode}) not supported')
            return ResponseCode.NOT_IMPLEMENTED

        return ResponseCode.NO_ERROR

    @classmethod
    def from_bytes(cls, data: bytes) -> "HeaderFlags":
        #: first bit of byte 3
        _qr: int = (data[0] & 0b10000000) >> 7
        #: bits 2-5 of byte 3
        _opcode: int = (data[0] & 0b01111000) >> 3
        #: bit 6 of byte 3
        _aa: int = (data[0] & 0b00000100) >> 2
        #: bit 7 of byte 3
        _tc: int = (data[0] & 0b00000010) >> 1
        #: bit 8 of byte 3
        _rd: int = (data[0] & 0b00000001)
        #: first bit of byte 4
        _ra: int = (data[1] & 0b10000000) >> 7
        #: bits 2-4 of byte 4 (3 unused bits)
        _z: int = (data[1] & 0b01110000) >> 4
        #: bits 5-8 of byte 4
        _rcode: int = (data[1] & 0b00001111)

        debug(qr=_qr, opcode=_opcode, aa=_aa, tc=_tc, rd=_rd, ra=_ra, z=_z,
              rcode=_rcode, data=data, offset=0)

        return cls(qr=_qr, opcode=_opcode, aa=_aa, tc=_tc, rd=_rd, ra=_ra,
                   z=_z, rcode=_rcode)

    @classmethod
    def empty(cls) -> "HeaderFlags":
        return cls(qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0,)


@dataclass
class Header:
    #: A 16 bit identifier assigned by the program that generates any kind of
    #: query. This identifier is copied the corresponding reply and can be used
    #: by the requester to match up replies to outstanding queries.
    id: int

    #: Header Flags Management
    flags: HeaderFlags = field(default_factory=HeaderFlags.empty)

    #: an unsigned 16 bit integer specifying the number of entries in the
    #: question section.
    qdcount: int = 0

    #: an unsigned 16 bit integer specifying the number of resource records in
    #: the answer section.
    ancount: int = 0

    #: an unsigned 16 bit integer specifying the number of name server resource
    #: records in the authority records
    nscount: int = 0

    #: an unsigned 16 bit integer specifying the number of resource records in
    #: the additional records section.
    arcount: int = 0

    def __bytes__(self) -> bytes:
        return struct.pack(
            '>HHHHHH',
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    def __copy__(self) -> 'Header':
        cls = self.__class__
        result = cls.__new__(cls)
        result.id = self.id
        result.flags = copy.copy(self.flags)
        result.qdcount = self.qdcount
        result.ancount = self.ancount
        result.nscount = self.nscount
        result.arcount = self.arcount

        return result

    def __repr__(self) -> str:
        return f'id: 0x{self.id:0>4x} / {self.id} - QUERY: {self.qdcount} '\
               f'ANSWER: {self.ancount} AUTHORITY: {self.nscount} '\
               f'ADDITIONAL: {self.arcount}'

    def serialize(self) -> bytes:
        return bytes(self)

    def validate(self) -> ResponseCode:
        return self.flags.validate()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        #: big endian
        _id: int = int.from_bytes(data[:2], 'big')

        flags = HeaderFlags.from_bytes(data[2:4])

        _qdcount: int = int.from_bytes(data[4:6], 'big')  # 2 bytes
        _ancount: int = int.from_bytes(data[6:8], 'big')  # 2 bytes
        _nscount: int = int.from_bytes(data[8:10], 'big')  # 2 bytes
        _arcount: int = int.from_bytes(data[10:12], 'big')  # 2 bytes

        return cls(id=_id, flags=flags, qdcount=_qdcount, ancount=_ancount,
                   nscount=_nscount, arcount=_arcount)

    @classmethod
    def empty(cls) -> "Header":
        import random
        _id = random.randint(0x0000, 0xFFFF)

        logger.info('Creating empty Header with ID: {_id}')
        return cls(
            id=_id,
            flags=HeaderFlags.empty(),
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0,
        )
