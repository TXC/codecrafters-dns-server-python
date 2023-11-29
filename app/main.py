import socket
import logging
import sys
from app.dns.message import Message
from app.dns.exceptions import DNSError


def main():
    address = ('127.0.0.1', 2053)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(address)

    root.info(f'Listening on {address[0]}:{address[1]}')

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            try:
                message: Message = Message.from_bytes(buf)

                response = message.create_response()

                udp_socket.sendto(response.serialize(), source)
            except DNSError as e:
                root.exception(e)

                from app.dns.header import Header
                header = Header.from_bytes(buf)
                header.flags.rcode = e.rcode
                response = Message(header=header)
                udp_socket.sendto(response.serialize(), source)

        except Exception as e:
            root.exception(e)
            break


if __name__ == "__main__":
    main()
