import struct
import logging
import copy
from dataclasses import dataclass, field
from app.dns.types import MessageType, OpCode, ResponseCode


@dataclass
class HeaderFlags:
    #: A one bit field that specifies whether this message is a query (0), or a
    #: response (1).
    qr: MessageType = MessageType.Query

    #: A four bit field that specifies kind of query in this message. This
    #: value is set by the originator of a query and copied into the response.
    opcode: OpCode = OpCode.QUERY

    #: Authoritative Answer - this bit is valid in responses, and specifies
    #: that the responding name server is an authority for the domain name in
    #: question section.
    aa: int = 0

    #: TrunCation - specifies that this message was truncated due to length
    #: greater than that permitted on the transmission channel.
    tc: int = 0

    #: Recursion Desired - this bit may be set in a query and is copied into
    #: the response.  If RD is set, it directs the name server to pursue the
    #: query recursively. Recursive query support is optional.
    rd: int = 0

    #: Recursion Available - this be is set or cleared in a response, and
    #: denotes whether recursive query support is available in the name server.
    ra: int = 0

    #: Reserved for future use.  Must be zero in all queries and responses.
    z: int = 0

    #: Response code - this 4 bit field is set as part of responses.
    rcode: ResponseCode = ResponseCode.NO_ERROR

    def __index__(self) -> int:
        return (
            (self.qr.value << 15)
            | (self.opcode.value << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | self.rcode.value
        )

    def __bytes__(self) -> bytes:
        return self.serialize()

    def __copy__(self) -> 'HeaderFlags':
        cls = self.__class__
        result = cls.__new__(cls)
        result.qr = MessageType(self.qr.value)
        result.opcode = OpCode(self.opcode.value)
        result.aa = self.aa
        result.tc = self.tc
        result.rd = self.rd
        result.ra = self.ra
        result.z = self.z
        result.rcode = ResponseCode(self.rcode.value)

        return result

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

        return cls(
            qr=MessageType(_qr),
            opcode=OpCode(_opcode),
            aa=_aa,
            tc=_tc,
            rd=_rd,
            ra=_ra,
            z=_z,
            rcode=ResponseCode(_rcode)
        )

    @classmethod
    def empty(cls) -> "HeaderFlags":
        return cls(
            qr=MessageType.Query,
            opcode=OpCode.QUERY,
            aa=0,
            tc=0,
            rd=0,
            ra=0,
            z=0,
            rcode=ResponseCode.NO_ERROR,
        )

    def serialize(self) -> bytes:
        return struct.pack('>H', int(self))


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
        return self.serialize()

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

        logging.info('Creating empty Header with ID: {_id}')
        return cls(
            id=_id,
            flags=HeaderFlags.empty(),
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0,
        )

    def serialize(self) -> bytes:
        return struct.pack(
            '>HHHHHH',
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )
