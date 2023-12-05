import unittest
from tests.common import TestDNS
from app.dns.header import Header
from app.dns.common import OpCode, ResponseCode, RClass, RType
from app.dns.message import Message
from app.dns.record import Query, ResourceRecord


class TestDNSMessage(TestDNS):
    @unittest.expectedFailure
    def test_message_empty(self) -> None:
        header = Header(id=1234)
        header.flags.qr = 1

        message = Message(header=header)

        res = message.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00'
        )
        actual = message.serialize()

        self.assertEqual(actual, expected)

    def test_message_with_question(self) -> None:
        testdata, bytedata = self.subtests[1]
        query = Query(name=testdata.name, type=testdata.type,
                      klass=testdata.klass)

        header = Header(id=1234)
        header.flags.qr = 1

        message = Message(
            header=header,
            queries=[query],
        )

        res = message.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            # Queryction
            + bytedata.name + bytedata.type + bytedata.klass
        )
        actual = message.serialize()

        self.assertEqual(actual, expected)

    def test_message_with_answer(self) -> None:
        testdata, bytedata = self.subtests[1]
        query = Query(name=testdata.name, type=testdata.type,
                      klass=testdata.klass)

        header = Header(id=1234)
        header.flags.qr = 1

        answer = ResourceRecord(
            name=testdata.name,
            type=testdata.type,
            klass=testdata.klass,
            ttl=testdata.ttl,
            rdlength=testdata.rdlength,
            rdata=testdata.rdata,
        )

        message = Message(
            header=header,
            queries=[query],
            answers=[answer]
        )

        res = message.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00'
            # Query Section
            + bytedata.name + bytedata.type + bytedata.klass
            # Answer section
            + bytedata.name + bytedata.type + bytedata.klass
            + bytedata.ttl + bytedata.rdlength + bytedata.rdata
        )
        actual = message.serialize()

        self.assertEqual(actual, expected)

    def test_message_from_bytes(self) -> None:
        s = (
            b'\x8b\x45\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x03\x77\x77\x77'                 # www
            b'\x06\x72\x65\x64\x64\x69\x74'     # reddit
            b'\x03\x63\x6f\x6d'                 # com
            b'\x00\x00\x01\x00\x01'
        )
        msg = Message.from_bytes(s)

        res = msg.validate()
        self.assertIsInstance(res, ResponseCode)
        self.assertEqual(res, ResponseCode.NO_ERROR)

        self.assertEqual(len(msg.queries), 1)
        self.assertEqual(len(msg.answers), 0)
        self.assertEqual(len(msg.authorities), 0)
        self.assertEqual(len(msg.additional), 0)

        self.assertEqual(msg.header.id, int.from_bytes(b'\x8b\x45', 'big'))
        self.assertEqual(msg.header.flags.qr, 0)
        self.assertEqual(msg.header.flags.opcode, OpCode.QUERY.value)
        self.assertEqual(msg.header.flags.aa, 0)
        self.assertEqual(msg.header.flags.tc, 0)
        self.assertEqual(msg.header.flags.rd, 1)
        self.assertEqual(msg.header.flags.ra, 0)
        self.assertEqual(msg.header.flags.z, 0)
        self.assertEqual(msg.header.flags.rcode, ResponseCode.NO_ERROR.value)

        self.assertEqual(msg.header.qdcount, 1)
        self.assertEqual(msg.header.ancount, 0)
        self.assertEqual(msg.header.nscount, 0)
        self.assertEqual(msg.header.arcount, 0)

        query = msg.queries.pop()

        self.assertIsInstance(query, Query)
        self.assertEqual(query.name, 'www.reddit.com')
        self.assertEqual(query.type, RType.A.value)
        self.assertEqual(query.klass, RClass.IN.value)


if __name__ == "__main__":
    unittest.main()
