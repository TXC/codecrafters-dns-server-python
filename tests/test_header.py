import unittest
from tests.common import TestDNS
from app.dns.header import Header, HeaderFlags
from app.dns.common import OpCode, ResponseCode


class TestDNSHeader(TestDNS):
    def test_flags_empty(self) -> None:
        flags = HeaderFlags.empty()

        self.assertEqual(flags.qr, 0)
        self.assertEqual(flags.opcode, OpCode.QUERY.value)
        self.assertEqual(flags.aa, 0)
        self.assertEqual(flags.tc, 0)
        self.assertEqual(flags.rd, 0)
        self.assertEqual(flags.ra, 0)
        self.assertEqual(flags.z, 0)
        self.assertEqual(flags.rcode, ResponseCode.NO_ERROR.value)

        self.assertEqual(flags.serialize(), b'\x00\x00')

    def test_flags_from_bytes(self) -> None:
        source = b'\x80\x00'
        flags = HeaderFlags.from_bytes(source)

        res = flags.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        self.assertEqual(flags.qr, 1)
        self.assertEqual(flags.opcode, OpCode.QUERY.value)
        self.assertEqual(flags.aa, 0)
        self.assertEqual(flags.tc, 0)
        self.assertEqual(flags.rd, 0)
        self.assertEqual(flags.ra, 0)
        self.assertEqual(flags.z, 0)
        self.assertEqual(flags.rcode, ResponseCode.NO_ERROR.value)

        self.assertEqual
        self.assertEqual(flags.serialize(), source)

    def test_flags(self) -> None:
        flags = HeaderFlags(qr=1)

        res = flags.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        self.assertEqual(flags.qr, 1)
        self.assertEqual(flags.opcode, OpCode.QUERY.value)
        self.assertEqual(flags.aa, 0)
        self.assertEqual(flags.tc, 0)
        self.assertEqual(flags.rd, 0)
        self.assertEqual(flags.ra, 0)
        self.assertEqual(flags.z, 0)
        self.assertEqual(flags.rcode, ResponseCode.NO_ERROR.value)

        self.assertEqual(flags.serialize(), b'\x80\x00')

    def test_header_empty(self) -> None:
        header = Header.empty()

        self.assertEqual(
            header.serialize()[2:],
            b'\x04\xd2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'[2:]
        )

    def test_header_from_bytes(self) -> None:
        source = b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        header = Header.from_bytes(source)

        res = header.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        self.assertEqual(
            header.serialize(),
            b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_header(self) -> None:
        header = Header(id=1357)

        res = header.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        self.assertEqual(
            header.serialize(),
            b'\x05\x4d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )


if __name__ == "__main__":
    unittest.main()
