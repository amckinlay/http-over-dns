import socket


def start():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("127.0.0.1", 1024))
        s.sendall(b"hi how are you?")
        print(s.recv(1024))
