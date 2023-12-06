import argparse
import socket
import logging
from app.dns.message import Message
from app.dns.exceptions import DNSError
from app.dns.common import setUpRootLogger

setUpRootLogger()
logger = logging.getLogger(__name__)


class DNSServer:
    address = ('127.0.0.1', 2053)
    # address = ('0.0.0.0', 2053)

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.handle_arguments()
        self.sock.bind(self.address)
        logger.info(f'Listening on {self.address[0]}:{self.address[1]}')

    def main(self) -> None:
        resolver = self.arg.resolver if 'resolver' in self.arg else None
        while True:
            buf, source = self.sock.recvfrom(512)
            if len(buf) == 0:
                break

            try:
                message: Message = Message.from_bytes(buf)

                response = message.create_response(resolver=resolver)

                res = response.serialize()
                self.sock.sendto(res, source)
            except socket.timeout:
                break
            except DNSError as e:
                logger.exception(e)
                self._create_error_response(e, buf, source)
            except Exception as e:
                logger.exception(e)
                break

    def _create_error_response(self, e: DNSError, buf: bytes,
                               source: any) -> None:
        from app.dns.header import Header
        header = Header.from_bytes(buf)
        header.flags.rcode = e.rcode.value
        header.ancount = 0
        header.nscount = 0
        header.arcount = 0
        response = Message(header=header)
        self.sock.sendto(response.serialize(), source)

    def handle_arguments(self):
        parser = argparse.ArgumentParser(
            description="Starts the server with an optional specified "
                        "resolver address."
        )

        parser.add_argument(
            "--resolver",
            type=self._parse_address,
            required=False,
            help="The resolver address in the format <ip>:<port>",
        )
        self.arg = parser.parse_args()

    def _parse_address(self, address: str) -> tuple[str, int]:
        """
        Parses the address string and returns a tuple of (ip, port).

        :param address: The address string in the format 'ip:port'.
        :type address: str
        :rtype: tuple[str, int]
        :return: A tuple containing the IP and port as separate elements.
        :raises argparse.ArgumentTypeError: If the address is not in the
                                            correct format.
        """

        try:
            if address.find(':') < 0:
                return address, 53

            ip, port_str = address.split(":")
            port = int(port_str)
            return ip, port
        except ValueError:
            raise argparse.ArgumentTypeError(
                "Address must be in the format 'ip:port'. "
                f"Received: '{address}'"
            )


if __name__ == "__main__":
    dns = DNSServer()
    dns.main()
