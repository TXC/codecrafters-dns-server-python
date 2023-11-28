#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_suites
----------------------------------

Tests for `app.dns`.
"""

import unittest
from typing import NamedTuple
from app.dns.types import MessageType, OpCode, ResponseCode, QClass, QType
from app.dns.header import Header, HeaderFlags
from app.dns.message import Message
from app.dns.record import Question, Record


class SubTest(NamedTuple):
    qname: str
    qtype: QType
    qclass: QClass
    ttl: int
    rdlength: int
    rdata: str
    qname_encoded: bytes
    qtype_encoded: bytes
    qclass_encoded: bytes
    ttl_encoded: bytes
    rdlength_encoded: bytes
    rdata_encoded: bytes


class TestDNS(unittest.TestCase):
    subtests = [
        SubTest(qname='google.com', qtype=QType.A, qclass=QClass.IN,
                ttl=3600, rdlength=4, rdata='1.2.3.4',
                qname_encoded=b'\x06google\x03com\x00',
                qtype_encoded=b'\x00\x01',
                qclass_encoded=b'\x00\x01',
                ttl_encoded=b'\x00\x00\x0e\x10',
                rdlength_encoded=b'\x00\x04',
                rdata_encoded=b'\x01\x02\x03\x04'
                ),
        SubTest(qname='codecrafters.io', qtype=QType.A, qclass=QClass.IN,
                ttl=60, rdlength=4, rdata='8.8.8.8',
                qname_encoded=b'\x0ccodecrafters\x02io\x00',
                qtype_encoded=b'\x00\x01',
                qclass_encoded=b'\x00\x01',
                ttl_encoded=b'\x00\x00\x00\x3c',
                rdlength_encoded=b'\x00\x04',
                rdata_encoded=b'\x08\x08\x08\x08'
                ),
        SubTest(qname='www.amazon.com', qtype=QType.CNAME, qclass=QClass.IN,
                ttl=7200, rdlength=10, rdata='amazon.com',
                qname_encoded=b'\x03www\x06amazon\x03com\x00',
                qtype_encoded=b'\x00\x05',
                qclass_encoded=b'\x00\x01',
                ttl_encoded=b'\x00\x00\x1c\x20',
                rdlength_encoded=b'\x00\x0A',
                rdata_encoded=b'amazon\x2ecom'
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
            header.serialize(),
            b'\x04\xd2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
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
        question = Question(qname=data.qname, qtype=data.qtype)

        header = Header(id=1234)
        header.flags.qr = MessageType.Response

        message = Message(
            header=header,
            questions=[question],
        )

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            # Question Section
            + data.qname_encoded + data.qtype_encoded + data.qclass_encoded
        )
        actual = message.serialize()

        self.assertEqual(actual, expected)

    def test_message_with_answer(self) -> None:
        data = self.subtests[1]
        question = Question(qname=data.qname, qtype=data.qtype)

        header = Header(id=1234)
        header.flags.qr = MessageType.Response

        answer = Record(
            qname=data.qname,
            qtype=data.qtype,
            ttl=data.ttl,
            rdlength=data.rdlength,
            rdata=data.rdata,
        )

        message = Message(
            header=header,
            questions=[question],
            answers=[answer]
        )

        expected = (
            # |  ID   | FLAGS |  QD   |  AN   |  NS   |  AR   |
            b'\x04\xd2\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00'
            # Question Section
            + data.qname_encoded + data.qtype_encoded + data.qclass_encoded
            # Answer section
            + data.qname_encoded + data.qtype_encoded + data.qclass_encoded
            + data.ttl_encoded + data.rdlength_encoded + data.rdata_encoded
        )
        actual = message.serialize()

        self.assertEqual(actual, expected)


class TestDNSRecord(TestDNS):
    def test_question_encoding(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                self.assertEqual(
                    Question.encode(source.qname),
                    source.qname_encoded
                )

    def test_question_from_bytes(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                question = Question.from_bytes(
                    source.qname_encoded
                    + source.qtype_encoded
                    + source.qclass_encoded
                )

                self.assertEqual(question.qname, source.qname)
                self.assertEqual(question.qtype, source.qtype)
                self.assertEqual(question.qclass, source.qclass)

    def test_question(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                question = Question(source.qname, source.qtype, source.qclass)
                self.assertEqual(
                    question.serialize(),
                    source.qname_encoded + source.qtype_encoded
                    + source.qclass_encoded
                )

    def test_record_encoding(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                self.assertEqual(
                    Record.encode(source.qname),
                    source.qname_encoded
                )

    def test_record_rdata_encoding(self) -> None:
        for source in self.subtests:
            if source.rdlength > 4:
                continue

            with self.subTest(source=source):
                self.assertEqual(
                    Record.encode(source.rdata), source.rdata_encoded
                )

    def test_record(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                record = Record(
                    qname=source.qname, qtype=source.qtype, ttl=source.ttl,
                    rdlength=source.rdlength, rdata=source.rdata
                )

                expected = (
                    source.qname_encoded + source.qtype_encoded
                    + source.qclass_encoded + source.ttl_encoded
                    + source.rdlength_encoded + source.rdata_encoded
                )

                self.assertEqual(record.serialize(), expected)


if __name__ == "__main__":
    unittest.main()
