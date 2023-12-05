import unittest
from tests.common import TestDNS
from app.dns.encoding import Encoding


class TestDNSEncoding(TestDNS):
    def test_encoder(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                testdata, bytedata = source
                self.assertEqual(Encoding.encode(testdata.name), bytedata.name)

    def test_decoder(self) -> None:
        for source in self.subtests:
            with self.subTest(source=source):
                testdata, bytedata = source
                actual, _ = Encoding.decode(bytedata.name)

                self.assertEqual(actual, testdata.name)


if __name__ == "__main__":
    unittest.main()
