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
import struct
from app.dns.common import ResponseCode, OpCode, setUpRootLogger
from app.dns.message import Message
from app.dns.header import Header, HeaderFlags
from tests.messages import test_messages
from tests import mock_socket
from app.main import DNSServer

# setUpRootLogger(logging.INFO)
setUpRootLogger()
logger = logging.getLogger(__name__)


class TestDNS(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()

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

    def test_message_socket(self) -> None:
        for subtest in test_messages:
            old_udp = DNSServer.udp
            DNSServer.logger = logger
            DNSServer.udp = mock_socket.MockSocket(mock_socket.AF_INET,
                                                   mock_socket.SOCK_DGRAM)
            server = DNSServer()
            title, data, raises = subtest
            server.udp.queue_recv(data)
            with self.subTest(title):
                server.main()

                header: Header = self.unpack_header(server.udp.last[:12])

                str_head = ';; ->>HEADER<<- opcode: {}, status: {}, id: {}\n'\
                           ';; flags: {!r}; QUERY: {}, ANSWER: {}, '\
                           'AUTHORITY: {}, ADDITIONAL: {}'

                print(str_head.format(
                    OpCode.safe_get_name_by_value(header.flags.opcode),
                    ResponseCode.safe_get_name_by_value(header.flags.rcode),
                    header.id,
                    header.flags,
                    header.qdcount,
                    header.ancount,
                    header.nscount,
                    header.arcount
                ))

                self.assertTrue(ResponseCode.value_exists(header.flags.rcode))
                self.assertEqual(header.flags.rcode, raises.value)

            DNSServer.udp = old_udp

    def unpack_header(self, data: bytes) -> Header:
        id, fl, qd, an, ns, ar = struct.unpack('>HHHHHH', data)

        flag_parameters = {
            'qr': (fl & 0x8000) >> 15,
            'opcode': (fl & 0x7800) >> 11,
            'aa': (fl & 0x0400) >> 10,
            'tc': (fl & 0x0200) >> 9,
            'rd': (fl & 0x0100) >> 8,
            'ra': (fl & 0x0080) >> 7,
            'z': (fl & 0x0070) >> 4,
            'rcode': (fl & 0x000f) >> 0,
        }

        header_parameters = {
            'id': id,
            'flags': HeaderFlags(**flag_parameters),
            'qdcount': qd,
            'ancount': an,
            'nscount': ns,
            'arcount': ar,
        }

        return Header(**header_parameters)


if __name__ == "__main__":
    unittest.main()
