import enum
import inspect
import logging
from typing import NewType

DomainName = NewType('DomainName', str)
CharacterString = NewType('CharacterString', str)
_Address = tuple[str, int] | str


def debug(message: str = '', *args: tuple, **kwarg: dict) -> None:
    info = caller_info()
    logger = logging.getLogger('.'.join([info[0], info[1]]))
    offset = kwarg['offset'] if 'offset' in kwarg else 0

    last_message = ''

    if len(args) > 0:
        x = 0
        for value in args:
            name = f'arg{x}'
            res = format_debug_message(value=value, name=name, offset=offset)
            message += res[0]
            last_message += res[1]
            x += 1

    if len(kwarg) > 0:
        for name, value in kwarg.items():
            if name == 'offset':
                continue

            res = format_debug_message(value=value, name=name, offset=offset)
            message += res[0]
            last_message += res[1]

    logger.debug(message + last_message + '\n')


def format_debug_message(
    value, name: str = '', offset: int = 0
) -> tuple[str, str]:
    format_str = '\n[{type}] {name}: {additional}{value}'

    message = ''
    last_message = ''
    tname = type(value)

    if isinstance(value, bytes):
        data_length = len(value) - offset
        p = stringify_bytes(value, offset)
        o = ''
        if offset > 0:
            o = f'{offset}+'
        last_message += format_str.format(
            type=tname.__name__,
            name=name,
            additional=f'({o}{data_length} bytes)',
            value=p
        )
    else:
        message += ', ' + format_str.format(
            type=tname.__name__,
            name=name,
            additional='',
            value=value
        )

    return message, last_message


def caller_info(skip=2):
    r"""Get the name of a caller in the format module.class.method.
    Copied from: https://gist.github.com/techtonik/2151727
    :param int skip: Specifies how many levels of stack
                     to skip while getting caller name.
                     skip=1 means "who calls me",
                     skip=2 "who calls my caller" etc.
    :rtype: str | tuple[str, str, str, str, int]
    :return: Returns a 5-tuple (package, module, class, caller, line)
             Or an empty string is returned if skipped levels exceed stack
             height.
             * package (string): caller package.
             * module (string): caller module.
             * klass (string): caller classname if one otherwise None.
             * caller (string): caller function or method (if a class exist).
             * line (int): the line of the call.
    """
    stack = inspect.stack()
    start = 0 + skip
    if len(stack) < start + 1:
        return ''
    parentframe = stack[start][0]

    # module and packagename.
    module_info = inspect.getmodule(parentframe)
    if module_info:
        mod = module_info.__name__.split('.')
        package = mod.pop(0)
        module = '.'.join(mod)

    # class name.
    klass = None
    if 'self' in parentframe.f_locals:
        klass = parentframe.f_locals['self'].__class__.__name__

    # method or function name.
    caller = None
    if parentframe.f_code.co_name != '<module>':  # top level usually
        caller = parentframe.f_code.co_name

    # call line.
    line = parentframe.f_lineno

    # Remove reference to frame
    # See: https://docs.python.org/3/library/inspect.html#the-interpreter-stack
    del parentframe

    return package, module, klass, caller, line


def stringify_bytes(value: bytes, offset: int = 0) -> str:
    p = ''
    data_length = len(value)
    for z in range(offset, data_length):
        if (z % 16) == 0 or z == offset:
            p += '\n'
        p += '\\x{:0>2x}'.format(value[z])
    return p


def get_random_ip() -> int:
    import random
    range_values = range(0, 255)
    str = '{}.{}.{}.{}'
    str = str.format(
        random.choice(range_values),
        random.choice(range_values),
        random.choice(range_values),
        random.choice(range_values),
    )
    return str


def get_random_ttl() -> int:
    import random
    ttl_values = [60, 300, 1800, 3600, 7200, 14400, 43200, 86400]
    return random.choice(ttl_values)


def setUpRootLogger(level: int = 0) -> logging.Logger:
    root = logging.getLogger()

    if not root.hasHandlers():
        import sys

        if level not in [logging.CRITICAL, logging.ERROR, logging.WARNING,
                         logging.INFO, logging.DEBUG,]:
            level = logging.DEBUG

        root.setLevel(level)

        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        )
        handler.setFormatter(formatter)
        root.addHandler(handler)
    return root


def exist_in_enum(value, enum_class: enum.Enum):
    values = set(item.value for item in enum_class)
    if value in values:
        return True
    return False


class EnumExtension(enum.Enum):
    @classmethod
    def value_exists(cls, value) -> bool:
        values = set(item.value for item in cls)
        if value in values:
            return True
        return False

    @classmethod
    def name_exists(cls, name) -> bool:
        names = set(item.name for item in cls)
        if name in names:
            return True
        return False

    @classmethod
    def safe_get_value_by_value(cls, key, default=None):
        if cls.value_exists(key):
            return cls(key).value
        return key if default is None else default

    @classmethod
    def safe_get_name_by_value(cls, key, default=None):
        if cls.value_exists(key):
            return cls(key).name
        return key if default is None else default

    @classmethod
    def safe_get_value_by_name(cls, key, default=None):
        if cls.name_exists(key):
            return cls[key].name
        return key if default is None else default

    @classmethod
    def safe_get_name_by_name(cls, key, default=None):
        if cls.name_exists(key):
            return cls[key].name
        return key if default is None else default


class RClass(EnumExtension):
    """Record Class"""

    #: the Internet
    IN = 1

    #: the CSNET class (Obsolete - used only for examples in some
    #: obsolete RFCs)
    CS = 2

    #: the CHAOS class
    CH = 3

    #: Hesiod [Dyer 87]
    HS = 4


class QClass(EnumExtension):
    """Query Class"""

    #: Any class
    ANY = 255


class RType(EnumExtension):
    """Record Type"""

    #: a host address
    A = 1

    #: an authoritative name server
    NS = 2

    #: a mail destination (Obsolete - use MX)
    MD = 3

    #: a mail forwarder (Obsolete - use MX)
    MF = 4

    #: the canonical name for an alias
    CNAME = 5

    #: marks the start of a zone of authority
    SOA = 6

    #: a mailbox domain name (EXPERIMENTAL)
    MB = 7

    #: a mail group member (EXPERIMENTAL)
    MG = 8

    #: a mail rename domain name (EXPERIMENTAL)
    MR = 9

    #: a null RR (EXPERIMENTAL)
    NULL = 10

    #: a well known service description
    WKS = 11

    #: a domain name pointer
    PTR = 12

    #: host information
    HINFO = 13

    #: mailbox or mail list information
    MINFO = 14

    #: mail exchange
    MX = 15

    #: text strings
    TXT = 16

    #: Information about the responsible person(s) for the domain.
    #: Usually an email address with the @ replaced by a .
    RP = 17

    AFSDB = 18
    SIG = 24
    KEY = 25
    AAAA = 28
    LOC = 29
    SRV = 33
    NAPTR = 35
    KX = 36
    CERT = 37
    DNAME = 39

    #: Pseudo-record type needed to support EDNS.
    # OPT = 41

    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SVCB = 64
    HTTPS = 65
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    URI = 256
    CAA = 257
    TA = 32768
    DLV = 32769


class QType(EnumExtension):
    """Query Class"""

    #: A request for a transfer of an entire zone
    AXFR = 252

    #: A request for mailbox-related records (MB, MG or MR)
    MAILB = 253

    #: A request for mail agent RRs (Obsolete - see MX)
    MAILA = 254

    #: A request for all records
    ANY = 255


class OpCode(EnumExtension):
    #: a standard query (QUERY)
    QUERY = 0

    #: an inverse query (IQUERY)
    # IQUERY = 1

    #: a server status request (STATUS)
    # STATUS = 2

    #: 3-15            reserved for future use


class ResponseCode(EnumExtension):
    NO_ERROR = 0
    """No error condition"""

    FORMAT_ERROR = 1
    """Format error - The name server was unable to interpret the query."""

    SERVER_FAILURE = 2
    """Server failure - The name server was unable to process this query due
    to a problem with the name server."""

    NAME_ERROR = 3
    """Name Error - Meaningful only for responses from an authoritative name
    server, this code signifies that the domain name referenced in the query
    does not exist."""

    NOT_IMPLEMENTED = 4
    """Not Implemented - The name server does not support the requested kind
    of query."""

    REFUSED = 5
    """Refused - The name server refuses to perform the specified operation for
    policy reasons.  For example, a name server may not wish to provide the
    information to the particular requester, or a name server may not wish to
    perform a particular operation (e.g., zone transfer) for particular data.
    """

    """6-15            Reserved for future use."""
