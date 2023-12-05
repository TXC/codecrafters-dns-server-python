import logging
import struct
from dataclasses import dataclass
from app.dns.encoding import Encoding
from app.dns.exceptions import NotImplementedError
from app.dns.common import RType, DomainName, CharacterString

logger = logging.getLogger(__name__)


@dataclass
class RDATA:
    @staticmethod
    def get_callable(record_type: int) -> tuple['RDATA', RType]:
        if not RType.value_exists(record_type):
            raise NotImplementedError(
                f'Unsupported Record Type: {record_type}'
            )

        t = RType(record_type)

        match t:
            case (
                    RType.CNAME | RType.MB | RType.MD | RType.MF | RType.MG
                    | RType.MR | RType.NS | RType.PTR):
                name = 'DOMAIN'

            case _:
                name = t.name.upper()

        from importlib import import_module
        obj = getattr(import_module('app.dns.rdata'), 'RDATA_' + name)
        return obj, t

    @staticmethod
    def factory(record_type: int, *args) -> 'RDATA':
        obj_path, t = RDATA.get_callable(record_type)
        obj: RDATA = obj_path()
        logger.info(f'Matched \'RType.{t.name}\' to \'{obj_path.__name__}\'')

        obj_annotations = getattr(obj, '__annotations__')
        if len(obj_annotations) > 0:
            a = 0
            for name, _type in obj_annotations.items():
                setattr(obj, name, _type(args[a]))
                a += 1
        return obj

    def __bytes__(self) -> bytes:
        return b''

    def __copy__(self):
        cls = self.__class__
        result = cls.__new__(cls)

        obj_annotations = getattr(self, '__annotations__')
        if len(obj_annotations) > 0:
            for name, _type in obj_annotations.items():
                old_value = getattr(self, name)
                setattr(result, name, _type(old_value))

        return result

    @classmethod
    def decode(cls, data: bytes) -> 'RDATA':
        return cls()


class RDATA_A(RDATA):
    data: DomainName

    def __bytes__(self) -> bytes:
        return Encoding.encode(self.data)

    @classmethod
    def factory(cls, *args) -> 'RDATA_A':
        return cls(*args)

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_A":
        name, _ = Encoding.decode_ip(data)
        return cls(data=name)


class RDATA_DOMAIN(RDATA):
    data: DomainName

    def __bytes__(self) -> bytes:
        return Encoding.encode(self.data)

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_DOMAIN":
        name, _ = Encoding.decode_domain_name(data)
        return cls(data=name)


class RDATA_HINFO(RDATA):
    cpu: CharacterString = ''
    os: CharacterString = ''

    def __bytes__(self) -> bytes:
        res = b''
        res += Encoding.encode_character_string(self.cpu)
        res += Encoding.encode_character_string(self.os)
        return res

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_HINFO":
        cpu, cpu_length = Encoding.decode_character_string(data)
        os, _ = Encoding.decode_character_string(
            data[cpu_length:]
        )
        return cls(cpu=cpu, os=os)


class RDATA_MINFO(RDATA):
    rmailbx: DomainName = ''
    emailbx: DomainName = ''

    def __bytes__(self) -> bytes:
        res = b''
        res += Encoding.encode_domain_name(self.rmailbx)
        res += Encoding.encode_domain_name(self.emailbx)

        return res

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_MINFO":
        rmailbx, _len = Encoding.decode_domain_name(data)
        emailbx, _ = Encoding.decode_domain_name(data[_len:])
        return cls(rmailbx=rmailbx, emailbx=emailbx)


class RDATA_MX(RDATA):
    preference: int = 0
    exchange: DomainName = ''

    def __bytes__(self) -> bytes:
        res = b''
        res += struct.pack("!H", self.preference)
        res += Encoding.encode_domain_name(self.exchange)
        return res

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_MX":
        preference = int.from_bytes(data[0:2], 'big')
        exchange = Encoding.decode_domain_name(data[2:])
        return cls(preference=preference, exchange=exchange, data=data)


class RDATA_SOA(RDATA):
    mname: DomainName = ''
    rname: DomainName = ''
    serial: int = 0
    refresh: int = 0
    retry: int = 0
    expire: int = 0
    minimum: int = 0

    def __bytes__(self) -> bytes:
        import struct

        res = b''
        res += Encoding.encode_domain_name(self.mname)
        res += Encoding.encode_domain_name(self.rname)
        res += struct.pack(
            '!LLLLL',
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        )
        return res

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_SOA":
        len = 0
        mname, _len = Encoding.decode_domain_name(data[len:])
        len += _len
        rname, _len = Encoding.decode_domain_name(data[len:])
        len += _len
        serial = int.from_bytes(data[len:4], 'big')
        len += 4
        refresh = int.from_bytes(data[len:4], 'big')
        len += 4
        retry = int.from_bytes(data[len:4], 'big')
        len += 4
        expire = int.from_bytes(data[len:4], 'big')
        len += 4
        minimum = int.from_bytes(data[len:4], 'big')
        len += 4

        return cls(
            mname=mname, rname=rname, serial=serial, refresh=refresh,
            retry=retry, expire=expire, minimum=minimum
        )


class RDATA_TXT(RDATA):
    data: CharacterString = ''

    def __bytes__(self) -> bytes:
        return Encoding.encode_character_string(self.data)

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_TXT":
        i = 0
        rdata: CharacterString = ''
        while i < len(data):
            _data, _i = Encoding.decode_character_string(data[i:])
            rdata += _data
            i += _i
        return cls(rdata)


class RDATA_NULL(RDATA):
    data: str = ''

    def __bytes__(self) -> bytes:
        return Encoding.encode_character_string(self.data)

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_NULL":
        rdata = data[:65535].decode('utf-8')
        return cls(rdata)


class RDATA_WKS(RDATA):
    address: DomainName
    protocol: int

    def __bytes__(self) -> bytes:
        res = b''
        res += struct.pack("!H", self.preference)
        res += Encoding.encode_domain_name(self.exchange)
        return res

    @classmethod
    def factory(cls, *args) -> 'RDATA_A':
        return cls(*args)

    @classmethod
    def decode(cls, data: bytes) -> "RDATA_A":
        name, i = Encoding.decode_ip(data)
        protocol = int.from_bytes(data[i:i + 1], 'big')
        return cls(data=name)
