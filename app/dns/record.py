import struct
from dataclasses import dataclass
from app.dns.types import QType, QClass


@dataclass
class BaseRecord:
    qname: str
    qtype: QType = QType.A
    qclass: QClass = QClass.IN

    def serialize(self) -> bytes:
        pass

    @staticmethod
    def _encode_str(parts: list[str]) -> bytes:
        res = b''
        for part in parts:
            ascii_part = part.encode('ascii')
            res = res + len(ascii_part).to_bytes(1, 'big') + ascii_part

        res = res + b'\x00'
        return res

    @staticmethod
    def _encode_ip(parts: list[int]) -> bytes:
        res = b''
        for part in parts:
            res += int(part).to_bytes(1, 'big')
        return res

    @staticmethod
    def encode(value: str) -> bytes:
        parts = value.split('.')
        try:
            if isinstance(int(parts[0]), int):
                return BaseRecord._encode_ip(parts)
        except ValueError:
            return BaseRecord._encode_str(parts)


@dataclass
class Question(BaseRecord):
    def serialize(self) -> bytes:
        res = b''
        res = (
            res + self.encode(self.qname)
            + struct.pack('!HH', self.qtype.value, self.qclass.value)
        )

        return res

    @classmethod
    def from_bytes(cls, data: bytes) -> "Question":
        i = 0
        qname = ''
        while i < len(data):
            if data[i] == 0x00:
                break

            length = int.from_bytes(data[i:i+1], 'big')
            i += 1
            qname += data[i:i + length].decode('utf-8') + '.'
            i += length

        # print(i)
        # p = ''
        # for z in range(i, len(data)):
        #     p += '\\x{:0>2x}'.format(data[z])
        # print(p)

        qtype = int.from_bytes(data[i + 1:i + 3], 'big')
        qclass = int.from_bytes(data[i + 4: i + 6], 'big')

        if qname[-1] == '.':
            qname = qname[0:-1]

        # print('QN:', qname, 'QT:', qtype, 'QC:', qclass)

        return cls(
            qname=qname,
            qtype=QType(qtype),
            qclass=QClass(qclass)
        )


@dataclass
class Record(Question):
    ttl: int = 0
    rdlength: int = 0
    rdata: str | None = None

    def serialize(self):
        if self.qtype is QType.A:
            rdata = self.encode(self.rdata)
        else:
            rdata = self.rdata.encode('ascii')

        res = (
            self.encode(self.qname)
            + struct.pack(
                "!HHIH",
                self.qtype.value,
                self.qclass.value,
                self.ttl,
                self.rdlength
            )
            + rdata
        )

        return res
