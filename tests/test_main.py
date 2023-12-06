#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_suites
----------------------------------

Tests for `app.dns`.
"""

import unittest
import unittest.mock
import logging
import copy
import app.main
from app.dns.common import ResponseCode, setUpRootLogger, get_random_ttl
from app.dns.message import Message
from app.dns.record import ResourceRecord
from app.dns.rdata import RDATA
from tests.messages import test_messages
from tests.common import TestData
from tests import mock_socket

# setUpRootLogger(logging.INFO)
setUpRootLogger()
logger = logging.getLogger(__name__)


def create_response(*args, **kwargs):
    logger.info('A: {}; K: {}'.format(len(args), len(kwargs)))
    return mock_socket.socket


class TestDNS(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()

    def build_response(
        self, data: bytes | Message, payload: list[TestData]
    ) -> Message:
        if isinstance(data, Message):
            response = copy.copy(data)
        elif isinstance(data, bytes):
            response = Message.from_bytes(data)
        else:
            raise Exception

        response.header.ancount = len(payload)
        response.header.flags.qr = 1
        for a in payload:
            if a.ttl < 0:
                ttl = get_random_ttl()
            else:
                ttl = a.ttl

            response.answers.append(ResourceRecord(
                name=a.name, type=a.type, klass=a.klass, ttl=ttl,
                rdlength=a.rdlength, rdata=a.rdata
            ))

        return response

    def compare_subtest(self, msg: Message, answers: list[TestData]):
        self.assertEqual(msg.header.ancount, len(answers))
        for _ in range(msg.header.ancount):
            expected = answers.pop()
            actual: ResourceRecord = msg.answers.pop()

            self.assertEqual(actual.name, expected.name)
            self.assertEqual(actual.type, expected.type.value)
            self.assertEqual(actual.klass, expected.klass.value)
            if expected.ttl > 0:
                self.assertEqual(actual.ttl, expected.ttl)
            self.assertEqual(actual.rdlength, expected.rdlength)

            self.assertIsInstance(actual.rdata, RDATA)
            # self.assertEqual(actual.rdata, expected.rdata)

    def test_message(self) -> None:
        for source in test_messages:
            title, data, response = source
            with self.subTest(title):
                msg = Message.from_bytes(data)

                res = msg.validate()

                self.assertIsInstance(res, ResponseCode)
                self.assertEqual(res, response)

                self.assertEqual(msg.header.qdcount, 1)
                self.assertEqual(msg.header.ancount, 0)
                # self.assertEqual(msg.header.nscount, 0)
                # self.assertEqual(msg.header.arcount, 0)
                self.assertEqual(msg.header.flags.rcode,
                                 ResponseCode.NO_ERROR.value)

    def test_create_response(self) -> None:
        for subtest in test_messages:
            title, data, response = subtest

            with self.subTest(title):
                msg = Message.from_bytes(data)

                self.assertEqual(len(msg.queries), msg.header.qdcount)
                self.assertEqual(len(msg.answers), msg.header.ancount)
                self.assertEqual(len(msg.authorities), msg.header.nscount)
                self.assertEqual(len(msg.additional), msg.header.arcount)

                resp = msg.create_response()

                self.assertEqual(len(resp.queries), resp.header.qdcount)
                self.assertEqual(len(resp.answers), resp.header.ancount)
                self.assertEqual(len(resp.authorities), resp.header.nscount)
                self.assertEqual(len(resp.additional), resp.header.arcount)

                self.assertEqual(resp.header.id, msg.header.id)
                self.assertEqual(resp.header.flags.qr, 1)
                self.assertEqual(resp.header.flags.opcode,
                                 msg.header.flags.opcode)
                self.assertEqual(resp.header.flags.rcode, response.value)
                self.assertIsInstance(resp.serialize(), bytes)

    @unittest.mock.patch('sys.argv', ['main.py'])
    @unittest.mock.patch('app.main.socket', mock_socket)
    def test_message_socket(self) -> None:
        for subtest in test_messages:
            server = app.main.DNSServer()
            title, data, raises, answers = subtest

            server.sock.queue_recv(data)
            with self.subTest(title):
                server.main()

                msg = Message.from_bytes(server.sock.last)

                print(f'{msg.header!r}')

                self.assertTrue(
                    ResponseCode.value_exists(msg.header.flags.rcode)
                )
                self.assertEqual(msg.header.flags.rcode, raises.value)
                self.compare_subtest()

    @unittest.mock.patch('sys.argv', ['main.py', '--resolver', '8.8.8.8'])
    @unittest.mock.patch('app.main.socket', mock_socket)
    @unittest.mock.patch('app.dns.message.socket', mock_socket)
    def test_message_socket_with_resolver(self) -> None:
        for subtest in test_messages:
            server = app.main.DNSServer()

            title, data, raises, answers = subtest
            response = self.build_response(data, answers)

            bresponse = bytes(response)
            app.dns.message.socket.reply_with(bresponse)
            server.sock.queue_recv(data)
            with self.subTest(title):
                server.main()

                msg = Message.from_bytes(server.sock.last)

                print(f'{msg.header!r}')

                self.assertTrue(
                    ResponseCode.value_exists(msg.header.flags.rcode)
                )
                self.assertEqual(msg.header.flags.rcode, raises.value)
                self.compare_subtest()


if __name__ == "__main__":
    unittest.main()
