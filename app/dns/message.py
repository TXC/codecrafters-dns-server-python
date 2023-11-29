import copy
import logging
from dataclasses import dataclass, field
from app.dns.types import MessageType
from app.dns.header import Header
from app.dns.record import Query, Record

HeaderSections = list[Query] | list[Record]
SectionResponse = dict[str, HeaderSections]


@dataclass
class Message:
    header: Header | None = None
    queries: list[Query] = field(default_factory=[])
    answers: list[Record] = field(default_factory=[])
    authorities: list[Record] = field(default_factory=[])
    additional: list[Record] = field(default_factory=[])

    sections = {
        'queries': 'qdcount',
        'answers': 'ancount',
        'authorities': 'nscount',
        'additional': 'arcount',
    }

    def __copy__(self) -> 'Message':
        cls = self.__class__
        result = cls.__new__(cls)
        result.header = copy.copy(self.header)

        for key in Message.sections:
            newsection = []

            section = getattr(self, key)
            if len(section) > 0:
                for q in section:
                    qq = copy.copy(q)
                    newsection.append(qq)

            setattr(result, key, newsection)

        return result

    def serialize(self) -> bytes:
        if not isinstance(self.header, Header):
            logging.error('Missing Header object')
            raise AttributeError(
                'Missing Header',
                name='header',
                obj=self
            )

        if not isinstance(self.queries, list):
            logging.error('Missing Query object')
            raise AttributeError(
                'Missing Query',
                name='header',
                obj=self
            )

        for key, count in Message.sections.items():
            section = getattr(self, key)
            section_size = len(section)
            if section_size < 1:
                logging.info(f'Section {key} has no value')
                continue

            logging.info(
                f'Assigning size of {section} ({section_size}) to {key}'
            )
            setattr(self.header, count, section_size)

        res = self.header.serialize()

        for key in Message.sections:
            section = getattr(self, key)
            logging.info(f'Serializing section: {key}')
            for q in section:
                try:
                    res += q.serialize()
                except Exception as e:
                    logging.exception(e)
                    raise e
        return res

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        logging.info('Got {} bytes'.format(len(data)))
        header = Header.from_bytes(data[:12])

        try:
            container = cls._build_sections(data, header, 12)
        except AttributeError as e:
            logging.exception(e)
            raise e

        return cls(header=header, **container)

    def create_response(self) -> 'Message':
        message = copy.copy(self)
        # message = copy.deepcopy(self)
        message.header.flags.qr = MessageType.Response

        for query in message.queries:
            if message.answers is None:
                message.answers = []

            logging.info(f'Creating response for {query.name}')
            record = Record.lookup(query=query)
            message.answers.append(record)
            message.header.ancount += 1

        return message

    @staticmethod
    def _build_sections(data: bytes, header: Header,
                        position: int = 12) -> SectionResponse:

        container: dict[str, list[Query | Record]] = {}
        position = 12
        for key, count in Message.sections.items():
            if key not in container:
                container[key] = []

            logging.info(f'Checking {key}...')

            ranger = getattr(header, count)
            cls = Record
            if key == 'queries':
                cls = Query
                if ranger < 1:
                    raise AttributeError(
                        f'Attribute ({count}) requires a positive value',
                        name=count,
                        object=header,
                    )

            if ranger > 0:
                logging.info(f'Building {ranger} record(s) for {key}...')
                for _ in range(ranger):
                    inst = getattr(cls, 'from_bytes')
                    query = inst(data[position:])
                    container[key].append(query)
                    position += len(query)

        return container
