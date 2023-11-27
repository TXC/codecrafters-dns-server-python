import socket
from app.dns.header import Header, MessageType
from app.dns.question import Question, QClass, QType
from app.dns.message import Message


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            header: Header = Header.empty()
            header.qr = MessageType.Response

            question: Question = Question(
                qname='codecrafters.io',
                qtype=QType.A,
                qclass=QClass.IN
            )

            message = Message(header=header, questions=[question])

            udp_socket.sendto(message.serialize(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
