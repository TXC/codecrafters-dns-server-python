import unittest
from tests.common import TestDNS
from app.dns.record import Query, ResourceRecord
from app.dns.common import ResponseCode


class TestDNSRecord(TestDNS):
    def test_query_from_bytes(self) -> None:
        for source in self.subtests:
            testdata, bytedata = source
            with self.subTest(f'{testdata!r}'):
                question, _ = Query.from_bytes(bytedata.name
                                               + bytedata.type
                                               + bytedata.klass)

                res = question.validate()
                self.assertIsInstance(res, ResponseCode)
                self.assertEqual(res, ResponseCode.NO_ERROR)

                self.assertEqual(question.name, testdata.name)
                self.assertEqual(question.type, testdata.type.value)
                self.assertEqual(question.klass, testdata.klass.value)

    def test_query(self) -> None:
        for source in self.subtests:
            testdata, bytedata = source
            with self.subTest(f'{testdata!r}'):
                question = Query(testdata.name, testdata.type, testdata.klass)

                res = question.validate()
                self.assertIsInstance(res, ResponseCode)
                self.assertEqual(res, ResponseCode.NO_ERROR)

                self.assertEqual(
                    question.serialize(),
                    bytedata.name + bytedata.type + bytedata.klass
                )

    def test_record_rdata_encoding(self) -> None:
        for source in self.subtests:
            testdata, bytedata = source
            with self.subTest(f'{testdata!r}'):
                record = ResourceRecord(
                    name=testdata.name, type=testdata.type,
                    klass=testdata.klass, ttl=testdata.ttl,
                    rdlength=testdata.rdlength, rdata=testdata.rdata
                )
                _, encoded = record.encode_rdata()

                self.assertEqual(encoded, bytedata.rdata)

    def test_record(self) -> None:
        for source in self.subtests:
            testdata, bytedata = source
            with self.subTest(f'{testdata!r}'):
                record = ResourceRecord(
                    name=testdata.name, type=testdata.type,
                    klass=testdata.klass, ttl=testdata.ttl,
                    rdlength=testdata.rdlength, rdata=testdata.rdata
                )

                expected = (
                    bytedata.name + bytedata.type + bytedata.klass
                    + bytedata.ttl + bytedata.rdlength + bytedata.rdata
                )
                actual = record.serialize()

                # print(
                #     '\nActual:\t\t{}\nExpected:\t{}'.format(actual, expected)
                # )

                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
