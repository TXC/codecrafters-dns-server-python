#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_suites
----------------------------------

Tests for `app.dns`.
"""

import unittest
from typing import NamedTuple
from app.dns.common import MessageType, OpCode, ResponseCode, RClass, RType, \
     QClass, QType
from app.dns.rdata import RDATA, RDATA_A
from app.dns.header import Header, HeaderFlags
from app.dns.message import Message
from app.dns.encoding import Encoding
from app.dns.record import Query, Record


class SubTest(NamedTuple):
    name: str
    type: QType | RType
    class_: QClass | RClass
    ttl: int
    rdlength: int
    rdata: RDATA
    name_encoded: bytes
    type_encoded: bytes
    class_encoded: bytes
    ttl_encoded: bytes
    rdlength_encoded: bytes
    rdata_encoded: bytes


class TestDNS(unittest.TestCase):
    subtests = [
        SubTest(name='google.com', type=RType.A, class_=RClass.IN,
                ttl=3600, rdlength=4, rdata='1.2.3.4',
                name_encoded=b'\x06google\x03com\x00',
                type_encoded=b'\x00\x01',
                class_encoded=b'\x00\x01',
                ttl_encoded=b'\x00\x00\x0e\x10',
                rdlength_encoded=b'\x00\x04',
                rdata_encoded=b'\x01\x02\x03\x04'
                ),
        SubTest(name='codecrafters.io', type=RType.A, class_=RClass.IN,
                ttl=60, rdlength=4, rdata='8.8.8.8',
                name_encoded=b'\x0ccodecrafters\x02io\x00',
                type_encoded=b'\x00\x01',
                class_encoded=b'\x00\x01',
                ttl_encoded=b'\x00\x00\x00\x3c',
                rdlength_encoded=b'\x00\x04',
                rdata_encoded=b'\x08\x08\x08\x08'
                ),
        SubTest(name='www.amazon.com', type=RType.CNAME, class_=RClass.IN,
                ttl=7200, rdlength=12, rdata='amazon.com',
                name_encoded=b'\x03www\x06amazon\x03com\x00',
                type_encoded=b'\x00\x05',
                class_encoded=b'\x00\x01',
                ttl_encoded=b'\x00\x00\x1c\x20',
                rdlength_encoded=b'\x00\x0C',
                rdata_encoded=b'\x06amazon\x03com\x00'
                ),
    ]

    def setUp(self) -> None:
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()


class TestDNSHeader(TestDNS):
    def test_flags_empty(self) -> None:
        flags = HeaderFlags.empty()

        self.assertEqual(flags.qr, MessageType.Query)
        self.assertEqual(flags.opcode, OpCode.QUERY)
        self.assertEqual(flags.aa, 0)
        self.assertEqual(flags.tc, 0)
        self.assertEqual(flags.rd, 0)
        self.assertEqual(flags.ra, 0)
        self.assertEqual(flags.z, 0)
        self.assertEqual(flags.rcode, ResponseCode.NO_ERROR)

        self.assertEqual(flags.serialize(), b'\x00\x00')

    def test_flags_from_bytes(self) -> None:
        source = b'\x80\x00'
        flags = HeaderFlags.from_bytes(source)

        self.assertEqual(flags.qr, MessageType.Response)
        self.assertEqual(flags.opcode, OpCode.QUERY)
        self.assertEqual(flags.aa, 0)
        self.assertEqual(flags.tc, 0)
        self.assertEqual(flags.rd, 0)
        self.assertEqual(flags.ra, 0)
        self.assertEqual(flags.z, 0)
        self.assertEqual(flags.rcode, ResponseCode.NO_ERROR)

        self.assertEqual(flags.serialize(), source)

    def test_flags(self) -> None:
        flags = HeaderFlags(qr=MessageType.Response)

        self.assertEqual(flags.qr, MessageType.Response)
        self.assertEqual(flags.opcode, OpCode.QUERY)
        self.assertEqual(flags.aa, 0)
        self.assertEqual(flags.tc, 0)
        self.assertEqual(flags.rd, 0)
        self.assertEqual(flags.ra, 0)
        self.assertEqual(flags.z, 0)
        self.assertEqual(flags.rcode, ResponseCode.NO_ERROR)

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

        self.assertEqual(
            header.serialize(),
            b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_header(self) -> None:
        header = Header(id=1357)

        self.assertEqual(
            header.serialize(),
            b'\x05\x4d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )


class TestDNSMessage(TestDNS):
    @unittest.expectedFailure
    def test_message_empty(self) -> None:
        header = Header(id=1234)
        header.flags.qr = MessageType.Response

        message = Message(header=header)

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00'
        )
        actual = message.serialize()

        self.assertEqual(actual, expected)

    def test_message_with_question(self) -> None:
        data = self.subtests[1]
        query = Query(name=data.name, type=data.type)

        header = Header(id=1234)
        header.flags.qr = MessageType.Response

        message = Message(
            header=header,
            queries=[query],
        )

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            # Queryction
            + data.name_encoded + data.type_encoded + data.class_encoded
        )
        actual = message.serialize()

        self.assertEqual(actual, expected)

    def test_message_with_answer(self) -> None:
        data = self.subtests[1]
        query = Query(name=data.name, type=data.type)

        header = Header(id=1234)
        header.flags.qr = MessageType.Response

        answer = Record(
            name=data.name,
            type=data.type,
            ttl=data.ttl,
            rdlength=data.rdlength,
            rdata=data.rdata,
        )

        message = Message(
            header=header,
            queries=[query],
            answers=[answer]
        )

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00'
            # Query Section
            + data.name_encoded + data.type_encoded + data.class_encoded
            # Answer section
            + data.name_encoded + data.type_encoded + data.class_encoded
            + data.ttl_encoded + data.rdlength_encoded + data.rdata_encoded
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

        self.assertEqual(len(msg.queries), 1)
        self.assertEqual(len(msg.answers), 0)
        self.assertEqual(len(msg.authorities), 0)
        self.assertEqual(len(msg.additional), 0)

        self.assertEqual(msg.header.id, int.from_bytes(b'\x8b\x45', 'big'))
        self.assertEqual(msg.header.flags.qr, MessageType.Query)
        self.assertEqual(msg.header.flags.opcode, OpCode.QUERY)
        self.assertEqual(msg.header.flags.aa, 0)
        self.assertEqual(msg.header.flags.tc, 0)
        self.assertEqual(msg.header.flags.rd, 1)
        self.assertEqual(msg.header.flags.ra, 0)
        self.assertEqual(msg.header.flags.z, 0)
        self.assertEqual(msg.header.flags.rcode, ResponseCode.NO_ERROR)

        self.assertEqual(msg.header.qdcount, 1)
        self.assertEqual(msg.header.ancount, 0)
        self.assertEqual(msg.header.nscount, 0)
        self.assertEqual(msg.header.arcount, 0)

        query = msg.queries.pop()

        self.assertIsInstance(query, Query)
        self.assertEqual(query.name, 'www.reddit.com')
        self.assertEqual(query.type, RType.A)
        self.assertEqual(query.class_, RClass.IN)

    def test_message_create_response(self) -> None:
        s = (
            b'\x8b\x45\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x03\x77\x77\x77'                 # www
            b'\x06\x72\x65\x64\x64\x69\x74'     # reddit
            b'\x03\x63\x6f\x6d'                 # com
            b'\x00\x00\x01\x00\x01'
        )
        msg = Message.from_bytes(s)
        response = msg.create_response()

        self.assertEqual(len(response.queries), 1)
        self.assertEqual(len(response.answers), 1)
        self.assertEqual(len(response.authorities), 0)
        self.assertEqual(len(response.additional), 0)

        self.assertEqual(
            response.header.id,
            int.from_bytes(b'\x8b\x45', 'big')
        )
        self.assertEqual(response.header.flags.qr, MessageType.Response)
        self.assertEqual(response.header.flags.opcode, OpCode.QUERY)
        self.assertEqual(response.header.flags.aa, 0)
        self.assertEqual(response.header.flags.tc, 0)
        self.assertEqual(response.header.flags.rd, 1)
        self.assertEqual(response.header.flags.ra, 0)
        self.assertEqual(response.header.flags.z, 0)
        self.assertEqual(response.header.flags.rcode, ResponseCode.NO_ERROR)

        self.assertEqual(response.header.qdcount, 1)
        self.assertEqual(response.header.ancount, 1)
        self.assertEqual(response.header.nscount, 0)
        self.assertEqual(response.header.arcount, 0)

        answer = response.answers.pop()

        self.assertIsInstance(answer, Record)
        self.assertEqual(answer.name, 'www.reddit.com')
        self.assertEqual(answer.type, RType.A)
        self.assertEqual(answer.class_, RClass.IN)
        self.assertGreater(answer.ttl, 0)
        self.assertEqual(answer.rdlength, 4)
        self.assertIsInstance(answer.rdata, RDATA_A)
        self.assertEqual(answer.rdata.data, '8.8.8.8')


class TestDNSEncoding(TestDNS):
    def test_encoder(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                self.assertEqual(
                    Encoding.encode(source.name),
                    source.name_encoded
                )

    def test_decoder(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                actual, _ = Encoding.decode(source.name_encoded)

                self.assertEqual(actual, source.name)


class TestDNSRecord(TestDNS):
    def test_query_from_bytes(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                question = Query.from_bytes(
                    source.name_encoded
                    + source.type_encoded
                    + source.class_encoded
                )

                self.assertEqual(question.name, source.name)
                self.assertEqual(question.type, source.type)
                self.assertEqual(question.class_, source.class_)

    def test_query(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                question = Query(source.name, source.type, source.class_)
                self.assertEqual(
                    question.serialize(),
                    source.name_encoded + source.type_encoded
                    + source.class_encoded
                )

    def test_record_rdata_encoding(self) -> None:
        for source in self.subtests:
            if source.rdlength > 4:
                continue

            with self.subTest(source=source):
                record = Record(
                    name=source.name, type=source.type, ttl=source.ttl,
                    rdlength=source.rdlength, rdata=source.rdata
                )
                encoded = record.encode_rdata()

                self.assertEqual(encoded, source.rdata_encoded)

    def test_record(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                record = Record(
                    name=source.name, type=source.type, ttl=source.ttl,
                    rdlength=source.rdlength, rdata=source.rdata
                )

                expected = (
                    source.name_encoded + source.type_encoded
                    + source.class_encoded + source.ttl_encoded
                    + source.rdlength_encoded + source.rdata_encoded
                )
                actual = record.serialize()

                # print(
                #     '\nActual:\t\t{}\nExpected:\t{}'.format(actual, expected)
                # )

                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
