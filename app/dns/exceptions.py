from app.dns.common import ResponseCode


class DNSError(Exception):
    rcode: ResponseCode = ResponseCode.NO_ERROR


class DNSServerFailure(Exception):
    rcode: ResponseCode = ResponseCode.SERVER_FAILURE


class FormatError(DNSError):
    rcode: ResponseCode = ResponseCode.FORMAT_ERROR


class NameError(DNSError):
    rcode: ResponseCode = ResponseCode.NAME_ERROR


class NotImplementedError(DNSError):
    rcode: ResponseCode = ResponseCode.NOT_IMPLEMENTED


class RefuseError(DNSError):
    rcode: ResponseCode = ResponseCode.REFUSED
