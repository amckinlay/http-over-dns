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


class DNSQuestion:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass


class DNSResourceRecord:
    def __init__(self, name, type_, class_, ttl, rdlength, rdata):
        self.name = name
        self.type = type_
        self.class_ = class_
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata


class DNSMessage:
    def __init__(self,
                 header,
                 questions=[],
                 answers=[],
                 authority=[],
                 additional=[]):
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional
