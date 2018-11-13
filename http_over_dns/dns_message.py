from dataclasses import dataclass, field
from typing import List, Type, TypeVar


def _encode_hostname(hostname: str) -> bytes:
    '''
    Encode a hostname into the length-value format used by DNS.
    '''
    encoded = b''
    for label in hostname.split('.'):
        encoded += (len(label).to_bytes(length=1, byteorder="big")
                    + label.encode("ascii"))
    # ensure null label
    if not encoded.endswith(b'\0'):
        encoded += b'\0'
    return encoded


def _decode_hostname(labels: bytes) -> str:
    '''
    Decode a hostname from the length-value format used by DNS.
    '''
    labels_list = []
    ptr = 0
    while ptr < len(labels):
        label_len = labels[ptr]
        ptr += 1
        labels_list.append(labels[ptr:ptr + label_len].decode("ascii"))
        ptr += label_len
    return ".".join(labels_list)


T = TypeVar('T', bound='DNSHeader')
@dataclass(frozen=True)
class DNSHeader:
    '''The header section of a DNS message.'''

    id: int
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    def encode(self) -> bytes:
        id_bytes = self.id.to_bytes(length=2, byteorder="big")
        third_byte = (self.qr << 7
                      | self.opcode << 6
                      | self.aa << 2
                      | self.tc << 1
                      | self.rd).to_bytes(length=1, byteorder="big")
        fourth_byte = (self.ra << 7 | self.rcode).to_bytes(length=1, byteorder="big")
        qdcount_bytes = self.qdcount.to_bytes(length=2, byteorder="big")
        ancount_bytes = self.ancount.to_bytes(length=2, byteorder="big")
        nscount_bytes = self.nscount.to_bytes(length=2, byteorder="big")
        arcount_bytes = self.arcount.to_bytes(length=2, byteorder="big")
        return (id_bytes
                + third_byte
                + fourth_byte
                + qdcount_bytes
                + ancount_bytes
                + nscount_bytes
                + arcount_bytes)

    @classmethod
    def decode(cls: Type[T], buf: bytes, ptr: int) -> (T, int):
        header = cls(id = int.from_bytes(buf[ptr:ptr + 2], byteorder="big"),
                     qr = bool(buf[ptr + 2] & (1 << 7)),
                     opcode = (buf[ptr + 2] >> 4) % (2 ** 5),
                     aa = bool(buf[ptr + 2] & (1 << 2)),
                     tc = bool(buf[ptr + 2] & (1 << 1)),
                     rd = bool(buf[ptr + 2] & 1),
                     ra = bool(buf[ptr + 3] & (1 << 7)),
                     rcode = buf[ptr + 3] % (2 ** 5),
                     qdcount = int.from_bytes(buf[ptr + 4:ptr + 6], byteorder="big"),
                     ancount = int.from_bytes(buf[ptr + 6:ptr + 8], byteorder="big"),
                     nscount = int.from_bytes(buf[ptr + 8:ptr + 10], byteorder="big"),
                     arcount = int.from_bytes(buf[ptr + 10:ptr + 12], byteorder="big"))
        return (header, ptr + 12)


T = TypeVar('T', bound='DNSQuestion')
@dataclass(frozen=True)
class DNSQuestion:
    '''Represents a question used to query a server in the questions section of a DNS message.'''

    qname: str
    qtype: int
    qclass: int

    def encode(self) -> bytes:
        return (_encode_hostname(self.qname)
                + self.qtype.to_bytes(length=2, byteorder="big")
                + self.qclass.to_bytes(length=2, byteorder="big"))

    @classmethod
    def decode(cls: Type[T], buf: bytes, ptr: int) -> (T, int):
        # find the last byte in qname (the null label)
        qname_end = buf.index(b'\0', ptr)
        qname_bytes = buf[ptr:qname_end + 1]
        ptr = qname_end + 1
        qtype_bytes = buf[ptr:ptr + 2]
        ptr += 2
        qclass_bytes = buf[ptr:ptr + 2]

        question = cls(qname = _decode_hostname(qname_bytes),
                       qtype = int.from_bytes(qtype_bytes, byteorder="big"),
                       qclass = int.from_bytes(qclass_bytes, byteorder="big"))
        return (question, ptr + 2)


T = TypeVar('T', bound='DNSResourceRecord')
@dataclass(frozen=True)
class DNSResourceRecord:
    '''Represents a DNS resource record used in the answer, authority, and additional sections of a DNS message.'''

    name: str
    type_: int
    class_: int
    ttl: int
    rdata: bytes

    def encode(self) -> bytes:
        return (_encode_hostname(self.name)
                + self.type_.to_bytes(length=2, byteorder="big")
                + self.class_.to_bytes(length=2, byteorder="big")
                + self.ttl.to_bytes(length=4, byteorder="big")
                + len(self.rdata).to_bytes(length=2, byteorder="big")
                + self.rdata)

    @classmethod
    def decode(cls: Type[T], buf: bytes, ptr: int) -> (T, int):
        # find the last byte in qname (the null label)
        qname_end = buf.index(b'\0', ptr)
        name_bytes = buf[ptr:qname_end + 1]
        ptr = qname_end + 1
        type_bytes = buf[ptr:ptr + 2]
        ptr += 2
        class_bytes = buf[ptr:ptr + 2]
        ptr += 2
        ttl_bytes = buf[ptr:ptr + 4]
        ptr += 4
        rdlength_bytes = buf[ptr:ptr + 2]
        ptr += 2

        rdlength = int.from_bytes(rdlength_bytes, byteorder="big")
        resource_record = cls(name = _decode_hostname(name_bytes),
                              type_ = int.from_bytes(type_bytes, byteorder="big"),
                              class_ = int.from_bytes(class_bytes, byteorder="big"),
                              ttl = int.from_bytes(ttl_bytes, byteorder="big"),
                              rdata = buf[ptr:ptr + rdlength])
        return (resource_record, ptr + 2)


T = TypeVar('T', bound='DNSMessage')
@dataclass(frozen=True)
class DNSMessage:
    '''Represents a DNS protocol message as defined by RFC 1035.'''

    header: DNSHeader
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSResourceRecord] = field(default_factory=list)
    authority: List[DNSResourceRecord] = field(default_factory=list)
    additional: List[DNSResourceRecord] = field(default_factory=list)
    
    def encode(self) -> bytes:
        msg = self.header.encode()

        for question in self.questions:
            msg += question.encode()

        for ans in self.answers:
            msg += ans.encode()

        for authoritative_ans in self.authority:
            msg += authoritative_ans.encode()

        for additional_ans in self.additional:
            msg += additional_ans.encode()

        return msg

    @classmethod
    def decode(cls: Type[T], buf: bytes) -> T:
        header, ptr = DNSHeader.decode(buf, 0)

        questions = []
        for _ in range(header.qdcount):
            question, ptr = DNSQuestion.decode(buf, ptr)
            questions.append(question)

        answers = []
        for _ in range(header.ancount):
            answer, ptr = DNSResourceRecord.decode(buf, ptr)
            answers.append(answer)

        authority = []
        for _ in range(header.arcount):
            authoritative_ans, ptr = DNSResourceRecord.decode(buf, ptr)
            authority.append(authoritative_ans)

        additional = []
        for _ in range(header.nscount):
            additional_ans, ptr = DNSResourceRecord.decode(but, ptr)
            additional.append(additional_ans)

        return cls(header=header,
                   questions=questions,
                   answers=answers,
                   authority=authority,
                   additional=additional)
