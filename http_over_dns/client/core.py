import socket

from http_over_dns.dns_message import DNSHeader, DNSMessage, DNSQuestion


def start():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("127.0.0.1", 1024))
        header = DNSHeader(
            id_=82,
            qr=False,
            opcode=0,
            aa=False,
            tc=False,
            rd=False,
            ra=False,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0)
        question = DNSQuestion(
            qname="testname.com",
            qtype=0,
            qclass=0)
        message = DNSMessage(
            header=header,
            questions=[question])
        s.sendall(message.encode())
