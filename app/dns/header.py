import enum
import struct
from dataclasses import dataclass
from .question import Question


class MessageType(enum.Enum):
    #: Message is a Query
    Query = 0

    #: Message is a Response
    Response = 1


class OpCode(enum.Enum):
    #: a standard query (QUERY)
    QUERY = 0

    #: an inverse query (IQUERY)
    IQUERY = 1

    #: a server status request (STATUS)
    STATUS = 2

    #: 3-15            reserved for future use


class ResponseCode(enum.Enum):
    #: No error condition
    NO_ERROR = 0b0000

    #: Format error - The name server was
    #: unable to interpret the query.
    FORMAT_ERROR = 0b0001

    #: Server failure - The name server was
    #: unable to process this query due to a
    #: problem with the name server.
    SERVER_FAILURE = 0b0010

    #: Name Error - Meaningful only for
    #: responses from an authoritative name
    #: server, this code signifies that the
    #: domain name referenced in the query does
    #: not exist.
    NAME_ERROR = 0b0011

    #: Not Implemented - The name server does
    #: not support the requested kind of query.
    NOT_IMPLEMENTED = 0b1000

    #: Refused - The name server refuses to
    #: perform the specified operation for
    #: policy reasons.  For example, a name
    #: server may not wish to provide the
    #: information to the particular requester,
    #: or a name server may not wish to perform
    #: a particular operation (e.g., zone
    #: transfer) for particular data.
    REFUSED = 0b1001

    #: 6-15            Reserved for future use.


@dataclass
class Header:
    #: A 16 bit identifier assigned by the program that generates any kind of
    #: query. This identifier is copied the corresponding reply and can be used
    #: by the requester to match up replies to outstanding queries.
    id: int

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
    questions: list[Question] | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> "Header":
        #: big endian
        _id: int = int.from_bytes(data[:2], 'big')
        #: first bit of byte 3
        _qr: int = (data[2] & 0b10000000) >> 7
        #: bits 2-5 of byte 3
        _opcode: int = (data[2] & 0b01111000) >> 3
        #: bit 6 of byte 3
        _aa: int = (data[2] & 0b00000100) >> 2
        #: bit 7 of byte 3
        _tc: int = (data[2] & 0b00000010) >> 1
        #: bit 8 of byte 3
        _rd: int = (data[2] & 0b00000001)
        #: first bit of byte 4
        _ra: int = (data[3] & 0b10000000) >> 7
        #: bits 2-4 of byte 4 (3 unused bits)
        _z: int = (data[3] & 0b01110000) >> 4
        #: bits 5-8 of byte 4
        _rcode: int = (data[3] & 0b00001111)

        _qdcount: int = int.from_bytes(data[4:6], 'big')  # 2 bytes
        _ancount: int = int.from_bytes(data[6:8], 'big')  # 2 bytes
        _nscount: int = int.from_bytes(data[8:10], 'big')  # 2 bytes
        _arcount: int = int.from_bytes(data[10:12], 'big')  # 2 bytes

        return cls(id=_id, qr=MessageType(_qr), opcode=OpCode(_opcode), aa=_aa,
                   tc=_tc, rd=_rd, ra=_ra, z=_z, rcode=ResponseCode(_rcode),
                   qdcount=_qdcount, ancount=_ancount, nscount=_nscount,
                   arcount=_arcount)

    @classmethod
    def empty(cls) -> "Header":
        return cls(
            id=1234,
            qr=MessageType.Response,
            opcode=OpCode.QUERY,
            aa=0,
            tc=0,
            rd=0,
            ra=0,
            z=0,
            rcode=ResponseCode.NO_ERROR,
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0,
        )

    def serialize(self) -> bytes:
        flags = (
            (self.qr.value << 15)
            | (self.opcode.value << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | self.rcode.value
        )

        return struct.pack(
            '>HHHHHH',
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )
