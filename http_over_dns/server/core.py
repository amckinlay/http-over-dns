from socketserver import DatagramRequestHandler, UDPServer



class DNSRequestHandler(DatagramRequestHandler):
    def handle(self):
        print(f"received the following from {self.client_address}:")
        for line in self.rfile:
            self.wfile.write(line)


def start():
    print("started!")
    with UDPServer(("127.0.0.1", 53),
                                DNSRequestHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("exiting!")
