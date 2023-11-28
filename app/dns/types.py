import enum


Label = str


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
