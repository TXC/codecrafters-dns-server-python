import socket
from app.dns.message import Message
from app.dns.exceptions import DNSError
from app.dns.common import setUpRootLogger


class DNSServer:
    address = ('127.0.0.1', 2053)
    # address = ('0.0.0.0', 2053)
    # udp = None
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logger = None

    def __init__(self):
        if self.logger is None:
            self.logger = setUpRootLogger()

        self.udp.bind(self.address)
        self.logger.info(f'Listening on {self.address[0]}:{self.address[1]}')

    def main(self) -> None:
        while True:
            buf, source = self.udp.recvfrom(512)
            if len(buf) == 0:
                break

            try:
                message: Message = Message.from_bytes(buf)

                response = message.create_response()

                res = response.serialize()
                self.udp.sendto(res, source)
            except socket.timeout:
                break
            except DNSError as e:
                self.logger.exception(e)
                self._create_error_response(e, buf, source)
            except Exception as e:
                self.logger.exception(e)
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
        self.udp.sendto(response.serialize(), source)


if __name__ == "__main__":
    dns = DNSServer()
    dns.main()
