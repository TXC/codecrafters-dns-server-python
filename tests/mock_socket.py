"""Mock socket module"""

# imported for _GLOBAL_DEFAULT_TIMEOUT
import sys
import socket as socket_module
from typing import TYPE_CHECKING, overload

_FD = int | str | bytes
WriteableBuffer = int | str | bytes
ReadableBuffer = int | str | bytes
_Address = int | str | bytes
_RetAddress = int | str | bytes

if TYPE_CHECKING:
    import _typeshed as _typeshed_module
    _FD = socket_module._FD

    # ReadOnlyBuffer = _typeshed_module.ReadOnlyBuffer
    WriteableBuffer = _typeshed_module.WriteableBuffer
    ReadableBuffer = _typeshed_module.ReadableBuffer

    _Address = socket_module._Address
    _RetAddress = socket_module._RetAddress

# Mock socket module
_defaulttimeout: float | None = None
_reply_data = None

# This is used to queue up data to be read through socket.makefile, typically
# *before* the socket object is even created. It is intended to handle a single
# line which the socket will feed on recv() or makefile().


def reply_with(line):
    global _reply_data
    _reply_data = line


class MockFile:
    """Mock file object returned by MockSocket.makefile().
    """
    def __init__(self, lines, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lines = lines

    def readline(self, limit=-1):
        result = self.lines.pop(0) + b'\r\n'
        if limit >= 0:
            # Re-insert the line, removing the \r\n we added.
            self.lines.insert(0, result[limit:-2])
            result = result[:limit]
        return result

    def close(self):
        pass


class MockSocket:
    """Mock socket object
    """
    def __init__(self, family: int = None, type: int = None,
                 proto: int = None, fileno: _FD = None) -> None:
        global _reply_data
        if fileno is None:
            if family is None:
                family = AF_INET
            if type is None:
                type = SOCK_STREAM
            if proto is None:
                proto = 0

        self.family = family
        self.type = type
        self.proto = proto
        self.fd = fileno
        self.last: WriteableBuffer | None = None
        self.output = []
        self.lines = []
        if _reply_data:
            self.lines.append(_reply_data)
            _reply_data = None
        self.conn = None
        self.timeout = None

    def dup(self):
        sock = self.__class__(self.family, self.type, self.proto,
                              fileno=self.fd)
        sock.settimeout(self.gettimeout())
        return sock

    def queue_recv(self, line: bytes) -> None:
        self.lines.append(line)

    def recv(self, bufsize: int, flags: int = None) -> bytes:
        if len(self.lines) < 1:
            return b''

        data = self.lines.pop(0) + b'\r\n'
        return data

    def recvfrom(self, bufsize: int,
                 flags: int = None) -> tuple[bytes, _RetAddress]:
        if len(self.lines) < 1:
            return (b'', self.getpeername())

        data = self.lines.pop(0) + b'\r\n'
        return (data, self.getpeername())

    def recvfrom_into(self, buffer: WriteableBuffer, nbytes: int = None,
                      flags: int = None) -> tuple[int, _RetAddress]:
        if len(self.lines) < 1:
            return (0, self.getpeername())

        data = self.lines.pop(0) + b'\r\n'
        if nbytes is None:
            nbytes = len(data)
        buffer.append(data)
        return (nbytes, self.getpeername())

    def recv_into(self, buffer: WriteableBuffer, nbytes: int = None,
                  flags: int = None) -> int:
        if len(self.lines) < 1:
            return 0

        data = self.lines.pop(0) + b'\r\n'
        if nbytes is None:
            nbytes = len(data)
        buffer.append(data)
        return nbytes

    def fileno(self) -> int:
        return 0

    def settimeout(self, timeout: float | None) -> None:
        if timeout is None:
            self.timeout = _defaulttimeout
        else:
            self.timeout = timeout

    def gettimeout(self) -> float | None:
        return self.timeout

    @overload
    def setsockopt(self, level: int, optname: int,
                   value: int | ReadableBuffer) -> None:
        pass

    def setsockopt(self, level: int, optname: int, value: None,
                   optlen: int) -> None:
        pass

    @overload
    def getsockopt(self, level: int, optname: int) -> int:
        return 0

    def getsockopt(self, level: int, optname: int,
                   buflen: int = None) -> bytes:
        return bytes()

    def bind(self, address: _Address) -> None:
        pass

    def accept(self) -> tuple['MockSocket', _Address]:
        self.conn = MockSocket()
        return self.conn, 'c'

    def getsockname(self) -> _RetAddress:
        return ('0.0.0.0', 0)

    def setblocking(self, flag: bool) -> None:
        pass

    def listen(self, backlog: int) -> None:
        pass

    def makefile(self, mode: str = "r", buffering: int = None, *,
                 encoding: str | None = None, errors: str | None = None,
                 newline: str | None = None):
        handle = MockFile(lines=self.lines, mode=mode, buffering=buffering,
                          encoding=encoding, errors=errors, newline=newline)
        return handle

    def sendall(self, data: ReadableBuffer, flags: int = None) -> None:
        self.last = data
        self.output.append(data)
        return len(data)

    def send(self, data: ReadableBuffer, flags: int = None) -> int:
        self.last = data
        self.output.append(data)
        return len(data)

    @overload
    def sendto(self, data: ReadableBuffer, address: _Address = None) -> int:
        self.last = data
        self.output.append(data)
        return len(data)

    def sendto(self, data: ReadableBuffer, flags: int = None,
               address: _Address = None) -> int:
        self.last = data
        self.output.append(data)
        return len(data)

    def getpeername(self) -> _RetAddress:
        return ('peer-address', 'peer-port')

    def close(self) -> None:
        pass

    def connect(self, host: _Address) -> None:
        pass

    def connect_ex(self, host: _Address) -> int:
        pass


def socket(family: int | None = None, type: int | None = None,
           proto: int | None = None, fileno: int | None = None) -> None:
    return MockSocket(family=family, type=type, proto=proto, fileno=fileno)


def create_connection(address: _Address,
                      timeout=socket_module._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None):
    try:
        int_port = int(address[1])  # noqa: F841
    except ValueError:
        raise error
    ms = MockSocket()
    if timeout is socket_module._GLOBAL_DEFAULT_TIMEOUT:
        timeout = getdefaulttimeout()
    ms.settimeout(timeout)
    return ms


def setdefaulttimeout(timeout: float | None):
    global _defaulttimeout
    _defaulttimeout = timeout


def getdefaulttimeout() -> float | None:
    return _defaulttimeout


def getfqdn() -> str:
    return ""


def gethostname() -> str:
    return ''


def gethostbyname(name: str) -> str:
    return ""


def getaddrinfo(*args, **kw):
    return socket_module.getaddrinfo(*args, **kw)


error = socket_module.error
herror = socket_module.herror
gaierror = socket_module.gaierror
timeout = socket_module.timeout


# Constants
_GLOBAL_DEFAULT_TIMEOUT = socket_module._GLOBAL_DEFAULT_TIMEOUT
has_ipv6: bool = socket_module.has_ipv6

AF_INET: int = socket_module.AF_INET
AF_INET6: int = socket_module.AF_INET6

SOCK_STREAM: int = socket_module.SOCK_STREAM
SOCK_DGRAM: int = socket_module.SOCK_DGRAM
SOCK_RAW: int = socket_module.SOCK_RAW
SOCK_RDM: int = socket_module.SOCK_RDM
SOCK_SEQPACKET: int = socket_module.SOCK_SEQPACKET

if sys.platform == "linux":
    SOCK_CLOEXEC: int = socket_module.SOCK_CLOEXEC
    SOCK_NONBLOCK: int = socket_module.SOCK_NONBLOCK

SOL_IP: int | None = None
SOL_SOCKET: int | None = None
SOL_TCP: int | None = None
SOL_UDP: int | None = None

SO_REUSEADDR = None

if hasattr(socket_module, 'AF_UNIX'):
    AF_UNIX = socket_module.AF_UNIX
