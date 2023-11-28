import socket
from app.dns.types import QType, QClass, MessageType
from app.dns.header import Header
from app.dns.message import Message
from app.dns.record import Question, Record


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            header: Header = Header.empty()
            header.flags.qr = MessageType.Response

            question: Question = Question(
                qname='codecrafters.io',
                qtype=QType.A,
                qclass=QClass.IN
            )

            answer: Record = Record(
                qname='codecrafters.io',
                qtype=QType.A,
                qclass=QClass.IN,
                ttl=60,
                rdlength=4,
                rdata='8.8.8.8'
            )

            message = Message(
                header=header,
                questions=[question],
                answers=[answer]
            )

            udp_socket.sendto(message.serialize(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
