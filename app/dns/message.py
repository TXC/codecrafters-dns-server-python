from dataclasses import dataclass
from .header import Header
from .question import Question

Label = str


@dataclass
class Message:
    header: Header | None = None
    questions: list[Question] | None = None

    def serialize(self) -> bytes:
        self.header.qdcount = len(self.questions)
        res = self.header.serialize()

        for q in self.questions:
            res = res + q.serialize()
        return res
