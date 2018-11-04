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
