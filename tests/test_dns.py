#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_suites
----------------------------------

Tests for `app.dns`.
"""

import unittest
from app.dns.header import Header, MessageType, OpCode, ResponseCode
from app.dns.question import Question, QClass, QType
from app.dns.message import Message


class TestDNS(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_question_encoding(self):
        google_encoded = Question.encode('google.com')
        ccio_encoded = Question.encode('codecrafters.io')

        self.assertEqual(
            google_encoded,
            b'\x06google\x03com\x00'
        )
        self.assertEqual(
            ccio_encoded,
            b'\x0ccodecrafters\x02io\x00'
        )

    def test_question_from_bytes(self):
        subtests = [
            (
                'google.com', QType.A, QClass.IN,
                b'\x06google\x03com\x00\x01\x00\x01'
            ),
            (
                'codecrafters.io', QType.CNAME, QClass.IN,
                b'\x0ccodecrafters\x02io\x00\x05\x00\x01',
            ),
        ]
        for source in subtests:
            with self.subTest(source=source):
                question = Question.from_bytes(source[3])

                self.assertEqual(question.qname, source[0])
                self.assertEqual(question.qtype, source[1])
                self.assertEqual(question.qclass, source[2])

    def test_question(self):
        question_ccio = Question(
            qname='codecrafters.io',
            qtype=QType.A,
            qclass=QClass.IN
        )
        question_google = Question(
            qname='google.com',
            qtype=QType.A,
            qclass=QClass.IN
        )

        self.assertEqual(
            question_ccio.serialize(),
            b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'
        )
        self.assertEqual(
            question_google.serialize(),
            b'\x06google\x03com\x00\x00\x01\x00\x01'
        )

    def test_header_empty(self):
        header = Header.empty()

        self.assertEqual(
            header.serialize(),
            b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_header_from_bytes(self):
        source = b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        header = Header.from_bytes(source)

        self.assertEqual(
            header.serialize(),
            b'\x04\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_header(self):
        header = Header(id=1357)

        self.assertEqual(
            header.serialize(),
            b'\x05M\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_message(self):
        question = Question(
            qname='codecrafters.io',
            qtype=QType.A,
        )

        header = Header(
            id=1234,
            qr=MessageType.Response,
            opcode=OpCode.QUERY,
            rcode=ResponseCode.NO_ERROR,
            qdcount=1,
            questions=[question]
        )
        message = Message(header=header, questions=[question])

        self.assertEqual(
            message.serialize(),
            b'\x04\xd2\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c'
            b'codecrafters\x02io\x00\x00\x01\x00\x01'
        )


if __name__ == "__main__":
    unittest.main()
