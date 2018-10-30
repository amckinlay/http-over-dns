def encode_hostname(hostname):
    encoded_hostname = b''
    for label in hostname.split(b'.'):
        encoded_hostname += bytes([len(label)]) + label
    return encoded_hostname


def decode_hostname(bytes_):
    decoded_hostname = b''
    ptr = 0
    while ptr < len(bytes_):
        label_len = bytes_[ptr]
        ptr += 1
        if label_len > 0:
            label = bytes_[ptr:ptr + label_len]
            decoded_hostname += label
        decoded_hostname += b'.'
        ptr += label_len
    return decoded_hostname


class DNSHeader:
    def __init__(self,
                 id_,
                 qr,
                 opcode,
                 aa,
                 tc,
                 rd,
                 ra,
                 rcode,
                 qdcount,
                 ancount,
                 nscount,
                 arcount):
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

    def encode(self):
        id_bytes = self.id.to_bytes(2, "big")
        third_byte = bytes([self.qr << 7
                            | self.opcode << 6
                            | self.aa << 2
                            | self.tc << 1
                            | self.rd])
        fourth_byte = bytes([self.ra << 7 | self.rcode])
        qdcount_bytes = self.qdcount.to_bytes(2, "big")
        ancount_bytes = self.ancount.to_bytes(2, "big")
        nscount_bytes = self.nscount.to_bytes(2, "big")
        arcount_bytes = self.arcount.to_bytes(2, "big")
        return (id_bytes
                + third_byte
                + fourth_byte
                + qdcount_bytes
                + ancount_bytes
                + nscount_bytes
                + arcount_bytes)


class DNSQuestion:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def encode(self):
        return encode_hostname(self.qname) + self.qtype + self.qclass

    def decode(self, bytes_):
        null_label_ptr = bytes_.find(b'\0')
        decoded_hostname = decode_hostname(bytes_[0:null_label_ptr + 1])
        decoded_qtype = bytes_[null_label_ptr + 1:null_label_ptr + 3]
        decoded_qclass = bytes_[null_label_ptr + 3:null_label_ptr + 5]
        # TODO: make decoder methods into class/static methods that construct objects


class DNSResourceRecord:
    def __init__(self, name, type_, class_, ttl, rdlength, rdata):
        self.name = name
        self.type = type_
        self.class_ = class_
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata

    def encode(self):
        return (encode_hostname(self.name)
                + self.type
                + self.class_
                + self.ttl.to_bytes(4, "big")
                + self.rdlength.to_bytes(2, "big")
                + self.rdata)


class DNSMessage:
    def __init__(self,
                 header,
                 questions=None,
                 answers=None,
                 authority=None,
                 additional=None):
        self.header = header
        self.questions = questions or []
        self.answers = answers or []
        self.authority = authority or []
        self.additional = additional or []

    def encode(self):
        encoded_msg = self.header.encode()
        for question in self.questions:
            encoded_msg += question.encode()
        for ans in self.answers:
            encoded_msg += ans.encode()
        for authoritative_ans in self.authority:
            encoded_msg += authoritative_ans.encode()
        for additional_ans in self.additional:
            encoded_msg += additional_ans.encode()
        return encoded_msg
