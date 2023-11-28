from dataclasses import dataclass
from app.dns.header import Header
from app.dns.record import Question, Record


@dataclass
class Message:
    header: Header | None = None
    questions: list[Question] | None = None
    answers: list[Record] | None = None

    def serialize(self) -> bytes:
        if not isinstance(self.header, Header):
            raise Exception('Missing Header')

        if not isinstance(self.questions, list):
            raise Exception('Missing Question list')

        if self.questions is not None and len(self.questions) > 0:
            self.header.qdcount = len(self.questions)

        if self.answers is not None and len(self.answers) > 0:
            self.header.ancount = len(self.answers)

        res = self.header.serialize()

        if self.questions is not None and len(self.questions) > 0:
            for q in self.questions:
                res += q.serialize()

        if self.answers is not None and len(self.answers) > 0:
            for q in self.answers:
                res += q.serialize()

        return res
