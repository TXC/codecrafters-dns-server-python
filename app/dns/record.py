import struct
import copy
from typing import TypeVar
from app.dns.types import RType, QType, RClass, QClass
from app.dns.rdata import RDATA
from app.dns.encoding import Encoding

RDATA_ARG = TypeVar('RDATA_ARG', RDATA, tuple[str | int, ...], str, int)


class BaseRecord:
    name: str
    type: RType = RType.A
    class_: RClass = RClass.IN
    size: int = 0

    def __init__(
        self, name: str, type: RType = RType.A, class_: RClass = RClass.IN,
        size: int = 0
    ):
        self.name = name
        self.type = type
        self.class_ = class_
        self.size = size

    def __copy__(self) -> 'BaseRecord':
        cls = self.__class__
        result = cls.__new__(cls)
        result.name = self.name
        result.type = RType(self.type.value)
        result.class_ = RClass(self.class_.value)

        return result

    def __len__(self) -> int:
        if not self.size:
            self.size = len(self.serialize())
        return self.size

    def serialize(self) -> bytes:
        pass

    @classmethod
    def from_bytes(cls, data: bytes) -> "BaseRecord":
        pass

    @staticmethod
    def _debug(pos: int, data: bytes) -> None:
        p = ''
        data_length = len(data)
        for z in range(pos, data_length):
            p += '\\x{:0>2x}'.format(data[z])

        print(f'\nInitial position: {pos}, Length: {data_length}\n{p}')


class Query(BaseRecord):
    type: RType | QType = RType.A
    class_: RClass | QClass = RClass.IN

    def __copy__(self) -> 'Query':
        cls = self.__class__
        result = cls.__new__(cls)
        result.name = self.name

        if isinstance(self.type, QType):
            result.type = QType(self.type.value)
        else:
            result.type = RType(self.type.value)

        if isinstance(self.class_, QClass):
            result.class_ = QClass(self.class_.value)
        else:
            result.class_ = RClass(self.class_.value)

        return result

    def serialize(self) -> bytes:
        res = b''
        res = (
            res + Encoding.encode(self.name)
            + struct.pack('!HH', self.type.value, self.class_.value)
        )

        return res

    @classmethod
    def from_bytes(cls, data: bytes) -> "Query":
        qname, i = Encoding.decode_domain_name(data)

        # cls._debug(i, data)

        _type = int.from_bytes(data[i:i + 2], 'big')
        i += 2
        _class = int.from_bytes(data[i: i + 2], 'big')
        i += 2

        # print('QN:', qname, 'QT:', qtype, 'QC:', qclass)

        return cls(
            name=qname,
            type=RType(_type),
            class_=RClass(_class),
            size=i
        )


class Record(BaseRecord):
    ttl: int = 0
    rdlength: int = 0
    rdata: RDATA | None = None

    def __init__(
        self, name: str, type: RType = RType.A, class_: RClass = RClass.IN,
        ttl: int = 0, rdlength: int = 0, rdata: RDATA_ARG | None = None
    ):
        super().__init__(name=name, type=type, class_=class_)
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = None

        if rdata is not None:
            self.rdata = RDATA.factory(type, rdata)

    def __copy__(self) -> 'Record':
        cls = self.__class__
        result = cls.__new__(cls)
        result.name = self.name
        result.type = RType(self.type.value)
        result.class_ = RClass(self.class_.value)

        result.ttl = self.ttl
        result.rdlength = self.rdlength
        result.rdata = copy.copy(self.rdata)

        return result

    def serialize(self):
        if isinstance(self.type, QType):
            raise Exception('Resource Record type can\'t have a QType')

        if isinstance(self.class_, QClass):
            raise Exception('Resource Record class can\'t have a QClass')

        rdata = self.encode_rdata()

        # self._debug(0, rdata)

        res = (
            Encoding.encode(self.name)
            + struct.pack(
                "!HHIH",
                self.type.value,
                self.class_.value,
                self.ttl,
                len(rdata)
            )
            + rdata
        )

        return res

    @classmethod
    def from_bytes(cls, data: bytes) -> "Record":
        name, i = Encoding.decode_domain_name(data)

        # cls._debug(i, data)

        i += 1
        _type = int.from_bytes(data[i:i + 2], 'big')
        i += 2
        _class = int.from_bytes(data[i: i + 2], 'big')
        i += 2
        ttl = int.from_bytes(data[i: i + 4], 'big')
        i += 4
        rdlength = int.from_bytes(data[i: i + 2], 'big')
        i += 2
        rdata = cls.decode_rdata(data[i: i + rdlength])
        i += rdlength

        # print(
        # 'QN:', qname,
        # 'QT:', qtype,
        # 'QC:', qclass,
        # 'TTL:', ttl,
        # 'RDLENGTH:', rdlength,
        # 'RDATA:', rdata
        # )

        return cls(
            name=name,
            type=RType(_type),
            class_=RClass(_class),
            ttl=ttl,
            rdlength=rdlength,
            rdata=rdata,
            size=i
        )

    @classmethod
    def lookup(cls, query: Query) -> 'Record':
        r_type = query.type
        r_class = query.class_

        if isinstance(r_class, QClass):
            r_class = RClass.IN

        if isinstance(r_type, QType):
            r_type = RType.A

        return cls(
            name=query.name,
            type=r_type,
            class_=r_class,
            ttl=cls.get_random_ttl(),
            rdlength=4,
            rdata='8.8.8.8'
        )

    @staticmethod
    def get_random_ttl() -> int:
        import random
        ttl_values = [60, 300, 1800, 3600, 7200, 14400, 43200, 86400]
        return random.choice(ttl_values)

    def decode_rdata(self, data: bytes) -> RDATA:
        if isinstance(self.rdata, RDATA):
            return self.rdata.decode(data)

        rdata = RDATA.get_callable(self.type)
        return rdata.decode(data)

    def encode_rdata(self) -> bytes:
        if isinstance(self.rdata, RDATA):
            return self.rdata.encode()

        rdata = RDATA.factory(self.type, self.rdata)

        return rdata.encode()
