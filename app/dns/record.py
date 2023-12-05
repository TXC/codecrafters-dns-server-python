import struct
import copy
import enum
import logging
from typing import TypeVar
from app.dns.common import RType, QType, RClass, QClass, ResponseCode, \
    debug, get_random_ttl
from app.dns.rdata import RDATA
from app.dns.encoding import Encoding

RDATA_ARG = TypeVar('RDATA_ARG', RDATA, tuple[str | int, ...], str, int)

logger = logging.getLogger(__name__)


class BaseRecord:
    name: str
    type: int

    bytes_read: int = 0
    bytes_written: int = 0

    def __init__(self, *args, **kwargs):
        """
        :param str name: Label of record
        :param int type: Record Type
        """
        total = len(args) + len(kwargs)
        if total < 2:
            cname = str(self.__class__)
            raise TypeError(
                f'{cname} takes 3 arguments but {total} were given'
            )

        if len(args) > 0:
            if 'name' not in kwargs:
                kwargs['name'] = args[0]
            if 'type' not in kwargs:
                kwargs['type'] = args[1]
        if len(kwargs) > 0:
            for name, value in kwargs.items():
                if isinstance(value, enum.Enum):
                    value = value.value
                setattr(self, name, value)

    def __copy__(self) -> 'BaseRecord':
        cls = self.__class__
        result = cls.__new__(cls)
        result.name = self.name
        result.type = self.type

        return result

    def __len__(self) -> int:
        return len(bytes(self))

    def __bytes__(self) -> bytes:
        res = (Encoding.encode(self.name)
               + struct.pack('!H', self.type))
        self.bytes_written = len(res)
        return res

    def __repr__(self) -> str:
        type = RType.safe_get_name_by_value(self.type)

        return f'BASE: {self.name} {type}'

    def serialize(self) -> bytes:
        return bytes(self)

    def validate(self) -> ResponseCode:
        if not RType.value_exists(self.type):
            logger.error('Record Type not supported')
            return ResponseCode.NOT_IMPLEMENTED

        return ResponseCode.NO_ERROR

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> "BaseRecord":
        debug('Base Payload', data=data)

        name, offset = Encoding.decode_domain_name(data, offset=offset)

        _type = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2

        obj = cls.__new__(cls)
        obj.name = name
        obj.type = _type
        obj.bytes_read = offset
        return obj

    @classmethod
    def factory(cls, data: bytes, offset: int = 0) -> 'BaseRecord':
        name, offset = Encoding.decode_domain_name(data, offset=offset)

        _type = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2

        if not RType.value_exists(_type):
            obj = cls.__new__(cls)
            obj.name = name
            obj.type = _type
            obj.bytes_read = offset
            return obj

        t = RType(_type)

        match t:
            case (
                    RType.A | RType.NS | RType.MD | RType.MF | RType.CNAME |
                    RType.SOA | RType.MB | RType.MG | RType.MR | RType.NULL |
                    RType.WKS | RType.PTR | RType.HINFO | RType.MINFO |
                    RType.MX | RType.TXT):
                resource = ResourceRecord
            case _:
                resource = BaseRecord

        return resource.from_bytes(data, offset=offset)


class Record(BaseRecord):
    klass: int

    def __init__(self, *args, **kwargs):
        """
        :param str name: Label of record
        :param int type: Record Type
        :param int klass: Record Class
        """
        super(Record, self).__init__(*args, **kwargs)
        total = len(args) + len(kwargs)
        if total < 3:
            cname = str(self.__class__)
            raise TypeError(
                f'{cname} takes 3 arguments but {total} were given'
            )

        if len(args) >= 3:
            if 'klass' not in kwargs:
                kwargs['klass'] = args[2]
        if len(kwargs) > 0:
            for name, value in kwargs.items():
                if isinstance(value, enum.Enum):
                    value = value.value
                setattr(self, name, value)

    def __copy__(self) -> 'Record':
        cls = self.__class__
        result = cls.__new__(cls)
        result.name = self.name
        result.type = self.type
        result.klass = self.klass

        return result

    def __repr__(self) -> str:
        if RType.value_exists(self.type):
            type = RType.safe_get_name_by_value(self.type)
        else:
            type = self.type

        if RClass.value_exists(self.klass):
            klass = RClass.safe_get_name_by_value(self.klass)
        else:
            klass = self.klass

        return f'R: {self.name} {klass} {type}'

    def __bytes__(self) -> bytes:
        res = (Encoding.encode(self.name)
               + struct.pack('!HH', self.type, self.klass))
        self.bytes_written = len(res)
        return res

    def validate(self) -> ResponseCode:
        pre = super(Record, self).validate()
        if pre != ResponseCode.NO_ERROR:
            return pre

        if not RClass.value_exists(self.klass):
            logger.error('Class not supported')
            return ResponseCode.NOT_IMPLEMENTED

        return ResponseCode.NO_ERROR

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> 'Record':
        newcls = super(Record, cls).from_bytes(data, offset=offset)

        offset = newcls.bytes_read
        klass = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2

        debug('RR', qn=newcls.name, qt=newcls.type, qc=klass)

        obj = cls.__new__(cls)
        obj.name = newcls.name
        obj.type = newcls.type
        obj.klass = klass
        obj.bytes_read = offset
        return obj


class Query(Record):
    def __repr__(self) -> str:
        if RClass.value_exists(self.klass):
            klass = RClass.safe_get_name_by_value(self.klass)
        elif QClass.value_exists(self.klass):
            klass = QClass.safe_get_name_by_value(self.klass)
        else:
            klass = self.klass

        if RType.value_exists(self.type):
            type = RType.safe_get_name_by_value(self.type)
        elif QType.value_exists(self.type):
            type = QType.safe_get_name_by_value(self.type)
        else:
            type = self.type

        return f'Q: {self.name} {klass} {type}'

    def validate(self) -> ResponseCode:
        # pre = super(Query, self).validate()
        # if pre != ResponseCode.NO_ERROR:
        #     return pre

        if (not RType.value_exists(self.type)
           and not QType.value_exists(self.type)):
            logger.error(
                f'Query Type ({self.type}) not supported'
            )
            return ResponseCode.NOT_IMPLEMENTED

        if (not RClass.value_exists(self.klass)
           and not QClass.value_exists(self.klass)):
            logger.error(
                f'Query Class ({self.klass}) not supported'
            )
            return ResponseCode.NOT_IMPLEMENTED

        return ResponseCode.NO_ERROR


class ResourceRecord(Record):
    ttl: int = 0
    rdlength: int = 0
    rdata: RDATA | None = None

    def __init__(self, *args, **kwargs):
        """
        :param str name: Label of record
        :param int type: Record Type
        :param int klass: Record Class
        :param int ttl: Record TTL
        :param int rdlength: Resource Record Data Length (RDLENGTH)
        :param rdata: Resource Record Data (RDATA)
        :type rdata: RDATA, tuple[str | int, ...], str, int
        """
        super(Record, self).__init__(*args, **kwargs)
        self.rdata = None

        total = len(args) + len(kwargs)
        if total < 6:
            raise TypeError(
                self.__class__ + f' takes 6 arguments but {total} were given'
            )
        if len(args) > 0:
            if 'ttl' not in kwargs:
                kwargs['ttl'] = args[3]
            if 'rdlength' not in kwargs:
                kwargs['rdlength'] = args[4]
            if 'rdata' not in kwargs:
                kwargs['rdata'] = args[5]
        if len(kwargs) > 0:
            for name, value in kwargs.items():
                if isinstance(value, enum.Enum):
                    value = value.value
                setattr(self, name, value)

        if self.rdata is not None:
            self.rdata = RDATA.factory(self.type, self.rdata)

    def __copy__(self) -> 'ResourceRecord':
        cls = self.__class__
        result = cls.__new__(cls)
        result.name = self.name
        result.type = self.type
        result.klass = self.klass

        result.ttl = self.ttl
        result.rdlength = self.rdlength
        result.rdata = copy.copy(self.rdata)

        return result

    def __repr__(self) -> str:
        klass = RClass.safe_get_name_by_value(self.klass)
        type = RType.safe_get_name_by_value(self.type)

        return f'R: {self.name} {klass} {type}'

    def __bytes__(self) -> bytes:
        rdlength, rdata = self.encode_rdata()

        debug(type=self.type, klass=self.klass, ttl=self.ttl,
              rdlength=rdlength, rdata=rdata)

        res = Encoding.encode(self.name)
        res += struct.pack("!HHIH",
                           self.type, self.klass, self.ttl, rdlength)
        res += rdata
        self.bytes_written = len(res)
        return res

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> 'ResourceRecord':
        newcls = super(ResourceRecord, cls).from_bytes(data, offset=offset)

        offset = newcls.bytes_read
        ttl = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4

        rdlength = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2

        rdata = cls.decode_rdata(data[offset:offset + rdlength])
        offset += rdlength

        obj = cls.__new__(cls)
        obj.name = newcls.name
        obj.type = newcls.type
        obj.klass = newcls.klass
        obj.ttl = ttl
        obj.rdlength = rdlength
        obj.rdata = rdata
        obj.bytes_read = offset
        return obj

    @classmethod
    def lookup(cls, query: Query) -> 'ResourceRecord':
        return cls(
            name=query.name,
            type=query.type,
            klass=query.klass,
            ttl=get_random_ttl(),
            rdlength=4,
            rdata='8.8.8.8'
        )

    def decode_rdata(self, data: bytes) -> RDATA:
        if len(data) < 1:
            return RDATA()

        if not isinstance(self.rdata, RDATA):
            self.rdata = RDATA.get_callable(self.type)

        return self.rdata.decode(data)

    def encode_rdata(self) -> tuple[int, bytes]:
        if not isinstance(self.rdata, RDATA):
            self.rdata = RDATA.factory(self.type, self.rdata)

        res = bytes(self.rdata)
        return len(res), res
