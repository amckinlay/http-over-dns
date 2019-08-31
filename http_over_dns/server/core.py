from base64 import b32decode, b32encode
from functools import partial
from socketserver import DatagramRequestHandler, UDPServer

from http_over_dns import DNSHeader, DNSMessage, DNSQuestion, DNSResourceRecord, decode_hostname, encode_hostname


DOMAIN = ""

SIZES = {}
SIZES['MESSAGE'] = 512
SIZES['HEADER'] = 12
SIZES['SESSION_ID'] = 8  # base32 32-bit uint
SIZES['COMMAND'] = 1
SIZES['SEQUENCE_NUMBER'] = 8  # base32 32-bit uint
SIZES['NAME'] = len(encode_hostname('.'.join(['X' * SIZES['SESSION_ID'],
                                              'X' * SIZES['COMMAND'],
                                              'X' * SIZES['SEQUENCE_NUMBER'],
                                              DOMAIN])))
SIZES['QUESTION_OVERHEAD'] = 4
SIZES['QUESTION'] = SIZES['QUESTION_OVERHEAD'] + SIZES['NAME']
SIZES['RESOURCE_RECORD'] = SIZES['MESSAGE'] - \
    SIZES['HEADER'] - SIZES['QUESTION']
SIZES['RESOURCE_RECORD_OVERHEAD'] = 10
SIZES['RESOURCE_RECORD_DATA'] = SIZES['RESOURCE_RECORD'] - \
    SIZES['RESOURCE_RECORD_OVERHEAD'] - SIZES["NAME"]

COMMANDS = {
    'SEND_MORE': 'S',
    'SEND_LAST': 'L',
    'RETRIEVE': 'R'
}


def _base32_encode(data: bytes) -> bytes:
    "Hostname-friendly b32encode. Replaces padding character = with 0."
    b32encode(data).replace(b'=', b'0')


def make_txt_segments(data: bytes) -> bytes:
    segment_length = SIZES["RESOURCE_RECORD_DATA"]
    for i in range(0, len(data), segment_length):
        yield data[i:i + segment_length]


def make_txt_records(session_id: int, data: bytes) -> DNSResourceRecord:
    for sequence_number, segment in enumerate(make_txt_segments(data)):
        session_id, sequence_number = map(
            lambda item: _base32_encode(item.to_bytes(
                length=1, byteorder="big")).decode(),
            (session_id, sequence_number))
        yield DNSResourceRecord(
            name=f'{session_id}.{COMMANDS["RETRIEVE"]}.{sequence_number}.{DOMAIN}',
            type=16,  # txt
            rdata=segment)


class DNSRequestHandler(DatagramRequestHandler):

    sessions = {}  # session_id -> bytes

    def handle(self):
        data = self.rfile.read()
        dns_message = DNSMessage.decode(data)
        hidden_data = b''
        for question in dns_message.questions:
            hidden_data += unhide_from_hostname(question.qname)
        session_id = hidden_data[0]
        self.sessions[session_id] += hidden_data[1:]


def start():
    print("server started!")
    with UDPServer(("127.0.0.1", 1024),
                   DNSRequestHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("exiting!")
