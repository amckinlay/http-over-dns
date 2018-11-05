from typing import List, Type, TypeVar


def encode_hostname(hostname: str) -> bytes:
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


def decode_hostname(labels: bytes) -> str:
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
class DNSHeader:
    '''The header section of a DNS message.'''

    def __init__(self,
                 id_: int,
                 qr: bool,
                 opcode: int,
                 aa: bool,
                 tc: bool,
                 rd: bool,
                 ra: bool,
                 rcode: int,
                 qdcount: int,
                 ancount: int,
                 nscount: int,
                 arcount: int):
        self.id = id_
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.arcount = arcount
        self.nscount = nscount

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
        header = cls(id_ = int.from_bytes(buf[ptr:ptr + 2], byteorder="big"),
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
class DNSQuestion:
    '''Represents a question used to query a server in the questions section of a DNS message.'''

    def __init__(self, qname: str, qtype: int, qclass: str):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def encode(self) -> bytes:
        return (encode_hostname(self.qname)
                + self.qtype.to_bytes(length=2, byteorder="big")
                + self.qclass.encode("ascii"))

    @classmethod
    def decode(cls: Type[T], buf: bytes, ptr: int) -> (T, int):
        # find the last byte in qname (the null label)
        qname_end = buf.index(b'\0', ptr)
        qname_bytes = buf[ptr:ptr + qname_end + 1]
        ptr += qname_end + 1
        qtype_bytes = buf[ptr:ptr + 2]
        ptr += 2
        qclass_bytes = buf[ptr:ptr + 2]

        question = cls(qname = decode_hostname(qname_bytes),
                       qtype = int.from_bytes(qtype_bytes, byteorder="big"),
                       qclass = qclass_bytes.decode("ascii"))
        return (question, ptr + 2)


T = TypeVar('T', bound='DNSResourceRecord')
class DNSResourceRecord:
    '''Represents a DNS resource record used in the answer, authority, and additional sections of a DNS message.'''

    def __init__(self, name: str, type_: int, class_: str, ttl: int, rdata: bytes):
        self.name = name
        self.type = type_
        self.class_ = class_
        self.ttl = ttl
        self.rdata = rdata

    def encode(self) -> bytes:
        return (encode_hostname(self.name)
                + self.type.to_bytes(length=2, byteorder="big")
                + self.class_.encode("ascii")
                + self.ttl.to_bytes(length=4, byteorder="big")
                + len(self.rdata).to_bytes(length=2, byteorder="big")
                + self.rdata)

    @classmethod
    def decode(cls: Type[T], buf: bytes, ptr: int) -> (T, int):
        # find the last byte in qname (the null label)
        qname_end = buf.index(b'\0', ptr)
        name_bytes = buf[ptr:ptr + qname_end + 1]
        ptr += qname_end + 1
        type_bytes = buf[ptr:ptr + 2]
        ptr += 2
        class_bytes = buf[ptr:ptr + 2]
        ptr += 2
        ttl_bytes = buf[ptr:ptr + 4]
        ptr += 4
        rdlength_bytes = buf[ptr:ptr + 2]
        ptr += 2

        rdlength = int.from_bytes(rdlength_bytes, byteorder="big")
        resource_record = cls(name = decode_hostname(name_bytes),
                              type_ = int.from_bytes(type_bytes, byteorder="big"),
                              class_ = class_bytes.decode("ascii"),
                              ttl = int.from_bytes(ttl_bytes, byteorder="big"),
                              rdata = buf[ptr:ptr + rdlength])
        return (resource_record, ptr + 2)


T = TypeVar('T', bound='DNSMessage')
class DNSMessage:
    '''Represents a DNS protocol message as defined by RFC 1035.'''

    def __init__(self,
                 header: DNSHeader,
                 questions: List[DNSQuestion] = None,
                 answers: List[DNSResourceRecord] = None,
                 authority: List[DNSResourceRecord] = None,
                 additional: List[DNSResourceRecord] = None):
        self.header = header
        self.questions = questions or []
        self.answers = answers or []
        self.authority = authority or []
        self.additional = additional or []

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