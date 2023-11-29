import copy
import logging
from dataclasses import dataclass, field
from app.dns.common import MessageType, debug
from app.dns.header import Header
from app.dns.record import BaseRecord, Query, Record

HeaderSections = list[Query] | list[Record]
SectionResponse = dict[str, HeaderSections]

logger = logging.getLogger(__name__)


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
            logger.error('Missing Header object')
            raise AttributeError(
                'Missing Header',
                name='header',
                obj=self
            )

        if not isinstance(self.queries, list):
            logger.error('Missing Query object')
            raise AttributeError(
                'Missing Query',
                name='header',
                obj=self
            )

        for key, count in Message.sections.items():
            section = getattr(self, key)
            section_size = len(section)
            if section_size < 1:
                logger.info(f'Section {key} has no value')
                continue

            logger.info(
                f'Assigning size of {section} ({section_size}) to {key}'
            )
            setattr(self.header, count, section_size)

        res = self.header.serialize()

        for key in Message.sections:
            section = getattr(self, key)
            logger.info(f'Serializing section: {key}')
            for q in section:
                try:
                    res += q.serialize()
                except Exception as e:
                    logger.exception(e)
                    raise e
        return res

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        debug(data=data)
        header = Header.from_bytes(data[:12])

        try:
            container = cls._build_sections(data, header, 12)
        except AttributeError as e:
            logger.exception(e)
            raise e

        return cls(header=header, **container)

    def create_response(self) -> 'Message':
        message = copy.copy(self)
        # message = copy.deepcopy(self)
        message.header.flags.qr = MessageType.Response

        for query in message.queries:
            if message.answers is None:
                message.answers = []

            logger.info(f'Creating response for {query.name}')
            record = Record.lookup(query=query)
            message.answers.append(record)
            message.header.ancount += 1

        return message

    @staticmethod
    def _build_sections(data: bytes, header: Header,
                        position: int = 12) -> SectionResponse:

        container: dict[str, list[Query | Record]] = {}
        for key, count in Message.sections.items():
            if key not in container:
                container[key] = []

            logger.info(f'Checking Header.{key}...')

            ranger = getattr(header, count)

            logger.info(f'Header.{key} reports {ranger} record(s)')

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
                logger.info(f'Building {ranger} record(s) for Header.{key}...')
                for _ in range(ranger):
                    try:
                        inst = getattr(cls, 'from_bytes')
                        rr: BaseRecord = inst(data[position:])
                        container[key].append(rr)
                        position += rr.bytes_read
                    except NotImplementedError as e:
                        setattr(header, count, ranger - 1)
                        logger.warning(e)
                        continue

        return container
