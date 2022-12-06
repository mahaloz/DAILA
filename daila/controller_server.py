from daila.controller import DAILAController
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

"""
What you want:
- Start a server that allows somone to send decomplation
- You send back identification string 
"""


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class DAILAServer:
    def __init__(self, host=None, port=None):
        self.host = host
        self.port = port
        self.running = False
        self.controller = DAILAController()

    #
    # Public API
    #
    def identify_function(self, decompilation: str):
        if not decompilation:
            print("NO DECOMPILATION")
            return ""

        success, result = self.controller.identify_decompilation(None, dec=decompilation)
        if not success or not isinstance(result, str):
            return ""

        return result

    #
    # XMLRPC Server
    #

    def ping(self):
        return True

    def shutdown(self):
        self.running = False

    def start_xmlrpc_server(self, host="localhost", port=44414):
        """
        Initialize the XMLRPC thread.
        """
        host = host or self.host
        port = port or self.port

        print("[+] Starting XMLRPC server: {}:{}".format(host, port))
        server = SimpleXMLRPCServer(
            (host, port),
            requestHandler=RequestHandler,
            logRequests=False,
            allow_none=True
        )
        server.register_introspection_functions()
        server.register_function(self.identify_function)
        server.register_function(self.ping)
        server.register_function(self.shutdown)
        print("[+] Registered decompilation server!")
        self.running = True
        while self.running:
            server.handle_request()
