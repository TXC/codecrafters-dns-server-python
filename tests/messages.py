from app.dns.common import ResponseCode, RType, RClass
from tests.common import TestData

TestMessage = tuple[str, bytes, ResponseCode, list[TestData] | None]

test_messages: list[TestMessage] = [
    (
        'QUERY NOERROR 0xf982 - codecrafters.io IN A',
        b'\xf9\x82\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x63\x6f'
        b'\x64\x65\x63\x72\x61\x66\x74\x65\x72\x73\x02\x69\x6f\x00\x00'
        b'\x01\x00\x01',
        ResponseCode.NO_ERROR,
        [TestData(name='codecrafters.io', type=RType.A, klass=RClass.IN,
                  ttl=-1, rdlength=4, rdata='8.8.8.8'),]
    ), (
        'QUERY NOERROR 0x8b45 - www.reddit.com IN A',
        b'\x8b\x45\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77'
        b'\x77\x06\x72\x65\x64\x64\x69\x74\x03\x63\x6f\x6d\x00\x00\x01'
        b'\x00\x01',
        ResponseCode.NO_ERROR,
        [TestData(name='www.reddit.com', type=RType.A, klass=RClass.IN,
                  ttl=-1, rdlength=4, rdata='8.8.8.8'),]
    ), (
        'QUERY NOERROR 0x37b9 - codecrafters.io IN A',
        b'\x37\xb9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x63\x6f'
        b'\x64\x65\x63\x72\x61\x66\x74\x65\x72\x73\x02\x69\x6f\x00\x00'
        b'\x01\x00\x01',
        ResponseCode.NO_ERROR,
        [TestData(name='codecrafters.io', type=RType.A, klass=RClass.IN,
                  ttl=-1, rdlength=4, rdata='8.8.8.8'),]
    ), (
        'QUERY FORMAT_ERROR 0x8670 - codecrafters.io IN A',
        b'\x86\x70\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x63\x6f'
        b'\x64\x65\x63\x72\x61\x66\x74\x65\x72\x73\x02\x69\x6f\x00\x00'
        b'\x01\x00\x01',
        ResponseCode.FORMAT_ERROR,
        []
    ), (
        'QUERY NOT_IMPLEMENTED 0xefac - codecrafters.io IN A +edns (OPT)',
        b'\xef\xac\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x0c\x63\x6f'
        b'\x64\x65\x63\x72\x61\x66\x74\x65\x72\x73\x02\x69\x6f\x00\x00'
        b'\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x0c\x00'
        b'\x0a\x00\x08\x22\xc6\x0c\x03\x1d\xad\x2d\x4d',
        # TypeError: ResourceRecord.decode_rdata() missing 1 required
        # positional argument: 'data'
        # TypeError
        ResponseCode.NOT_IMPLEMENTED,
        []
    ), (
        'QUERY FORMAT_ERROR 0x33d5 - codecrafters.io IN A +edns (OPT)',
        b'\x33\xd5\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x0c\x63\x6f'
        b'\x64\x65\x63\x72\x61\x66\x74\x65\x72\x73\x02\x69\x6f\x00\x00'
        b'\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x0c\x00'
        b'\x0a\x00\x08\x05\x98\x0d\xe2\xdf\xb5\xa4\x2b',
        ResponseCode.FORMAT_ERROR,
        []
    ), (
        'QUERY NOERROR 0x8b45 - www.reddit.com IN A',
        b'\x8b\x45\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77'
        b'\x77\x06\x72\x65\x64\x64\x69\x74\x03\x63\x6f\x6d\x00\x00\x01'
        b'\x00\x01',
        ResponseCode.NO_ERROR,
        [TestData(name='www.reddit.com', type=RType.A, klass=RClass.IN,
                  ttl=-1, rdlength=4, rdata='8.8.8.8'),]
    ), (
        'IQUERY NOT_IMPLEMENTED 0x9a1e - codecrafters.io IN A',
        b'\x9a\x1e\x08\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x63\x6f'
        b'\x64\x65\x63\x72\x61\x66\x74\x65\x72\x73\x02\x69\x6f\x00\x00'
        b'\x01\x00\x01',
        ResponseCode.NOT_IMPLEMENTED,
        []
    ), (
        'QUERY NOERROR 0x815f',
        b'\x81\x5f\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x63\x6f\x64'
        b'\x65\x63\x72\x61\x66\x74\x65\x72\x73\x02\x69\x6f\x00\x00\x01\x00'
        b'\x01',
        ResponseCode.NO_ERROR,
        [TestData(name='codecrafters.io', type=RType.A, klass=RClass.IN,
                  ttl=-1, rdlength=4, rdata='8.8.8.8'),]
    ), (
        'QUERY NOERROR 0x8bc9 - [abc,def].longassdomainname.com IN A',
        b'\x8b\xc9\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03\x61\x62\x63'
        b'\x11\x6c\x6f\x6e\x67\x61\x73\x73\x64\x6f\x6d\x61\x69\x6e\x6e\x61'
        b'\x6d\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x03\x64\x65\x66\xc0'
        b'\x10\x00\x01\x00\x01',
        ResponseCode.NO_ERROR,
        [
            TestData(name='abc.longassdomainname.com', type=RType.A,
                     klass=RClass.IN, ttl=-1, rdlength=4, rdata='8.8.8.8'),
            TestData(name='def.longassdomainname.com', type=RType.A,
                     klass=RClass.IN, ttl=-1, rdlength=4, rdata='8.8.8.8'),
        ]
    ),
]
