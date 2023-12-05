import unittest
from typing import NamedTuple
from app.dns.common import RClass, RType
from app.dns.rdata import RDATA


class TestData(NamedTuple):
    name: str
    type: RType
    klass: RClass
    ttl: int
    rdlength: int
    rdata: RDATA


class ByteData(NamedTuple):
    name: bytes
    type: bytes
    klass: bytes
    ttl: bytes
    rdlength: bytes
    rdata: bytes


SubtestTuple = tuple[TestData, ByteData]
SubtestList = list[SubtestTuple]


class TestDNS(unittest.TestCase):
    subtests: SubtestList = [
        (
            TestData(name='google.com', type=RType.A, klass=RClass.IN,
                     ttl=3600, rdlength=4, rdata='1.2.3.4'),
            ByteData(name=b'\x06google\x03com\x00', type=b'\x00\x01',
                     klass=b'\x00\x01', ttl=b'\x00\x00\x0e\x10',
                     rdlength=b'\x00\x04', rdata=b'\x01\x02\x03\x04')
        ), (
            TestData(name='codecrafters.io', type=RType.A, klass=RClass.IN,
                     ttl=60, rdlength=4, rdata='8.8.8.8'),
            ByteData(name=b'\x0ccodecrafters\x02io\x00', type=b'\x00\x01',
                     klass=b'\x00\x01', ttl=b'\x00\x00\x00\x3c',
                     rdlength=b'\x00\x04', rdata=b'\x08\x08\x08\x08')
        ), (
            TestData(name='www.amazon.com', type=RType.CNAME, klass=RClass.IN,
                     ttl=7200, rdlength=12, rdata='amazon.com'),
            ByteData(name=b'\x03www\x06amazon\x03com\x00', type=b'\x00\x05',
                     klass=b'\x00\x01', ttl=b'\x00\x00\x1c\x20',
                     rdlength=b'\x00\x0C', rdata=b'\x06amazon\x03com\x00')
        ),
    ]

    def setUp(self) -> None:
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()
