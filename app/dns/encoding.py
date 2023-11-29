from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.dns.types import CharacterString, DomainName


class Encoding:

    """Encoding Part"""
    @staticmethod
    def encode_domain_name(parts: list[str]) -> bytes:
        res = b''
        for part in parts:
            ascii_part = part.encode('ascii')
            res += len(ascii_part).to_bytes(1, 'big') + ascii_part

        res = res + b'\x00'
        return res

    @staticmethod
    def encode_character_string(value: 'CharacterString') -> bytes:
        res = b''
        ascii_value = value.encode('ascii')
        res += len(ascii_value).to_bytes(1, 'big') + ascii_value

        res = res + b'\x00'
        return res

    @staticmethod
    def encode_ip(parts: list[int]) -> bytes:
        res = b''
        for part in parts:
            res += int(part).to_bytes(1, 'big')
        return res

    @staticmethod
    def encode(value: str) -> bytes:
        value = value.replace('@', '.')
        value = value.replace('-', '.')
        value = value.replace('+', '.')
        parts = value.split('.')
        try:
            if isinstance(int(parts[0]), int):
                return Encoding.encode_ip(parts)
        except ValueError:
            return Encoding.encode_domain_name(parts)

    """Decoding Part"""
    @staticmethod
    def decode_domain_name(data: bytes) -> tuple['DomainName', int]:
        """
        Read from `data` until first NUL-byte is reached

        :param bytes data: Data to decode
        :rtype: tuple[str, int]
        :return: A 2-tuple, first is decoded data, second is bytes read
        """
        i = 0
        qname = ''
        while i < len(data):
            if data[i] == 0x00:
                i += 1
                break

            length = int.from_bytes(data[i:i+1], 'big')
            i += 1
            qname += data[i:i + length].decode('utf-8') + '.'
            i += length

        if qname[-1] == '.':
            qname = qname[0:-1]

        return (qname, i)

    @staticmethod
    def decode_character_string(data: bytes) -> tuple['CharacterString', int]:
        """
        Read length-octet from first byte, then read length-bytes from `data`

        :param bytes data: Data to decode
        :rtype: tuple[str, int]
        :return: A 2-tuple, first is decoded data, second is bytes read
        """
        length = int.from_bytes(data[:1], 'big')
        res = data[1:length].decode('utf-8')

        return (res, length + 1)

    @staticmethod
    def decode_ip(data: bytes) -> tuple[str, int]:
        res = '{}.{}.{}.{}'.format(
            int.from_bytes(data[0:1], 'big'),
            int.from_bytes(data[1:2], 'big'),
            int.from_bytes(data[2:3], 'big'),
            int.from_bytes(data[3:4], 'big'),
        )

        return (res, 4)

    @staticmethod
    def decode(data: bytes) -> tuple[str, int]:
        if data[-1] == b'\x00':
            return Encoding.decode_ip(data)
        else:
            return Encoding.decode_domain_name(data)
