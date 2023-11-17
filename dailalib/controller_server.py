from dailalib.ai_api.openai_api import OpenAIAPI
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from functools import wraps

class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def proxy_and_catch(func):
    @wraps(func)
    def _proxy_and_catch(self, *args, **kwargs):
        if not args or not args[0]:
            return ""

        try:
            output = func(self, *args, **kwargs)
        except Exception as e:
            if self.use_py2_exceptions:
                raise BaseException(*e.args)
            else:
                raise e

        return output
    return _proxy_and_catch


class DAILAServer:
    def __init__(self, host=None, port=None, use_py2_exceptions=False):
        self.host = host
        self.port = port
        self.running = False
        self.controller = OpenAIAPI()

        self.use_py2_exceptions = use_py2_exceptions

    #
    # Public API
    #
    @proxy_and_catch
    def identify_function(self, decompilation: str):
        if not decompilation:
            return ""

        result = self.controller.find_source_of_function(decompilation=decompilation)
        if not result:
            return ""

        return result

    @proxy_and_catch
    def explain_function(self, decompilation: str):
        if not decompilation:
            return ""

        result = self.controller.summarize_function(decompilation=decompilation)
        if not result:
            return ""

        return result

    @proxy_and_catch
    def find_vulns_function(self, decompilation: str):
        if not decompilation:
            return ""

        result = self.controller.find_vulnerability_in_function(decompilation=decompilation)
        if not result:
            return ""

        return result
    
    @proxy_and_catch
    def rename_func_and_vars_function(self, decompilation: str):
        if not decompilation:
            return ""

        result = self.controller.rename_variables_in_function(decompilation=decompilation)
        if not result:
            return ""

        return str(result)

    def set_api_key(self, api_key: str):
        if api_key:
            self.controller.api_key = api_key

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
        server.register_function(self.explain_function)
        server.register_function(self.find_vulns_function)
        server.register_function(self.rename_func_and_vars_function)
        server.register_function(self.set_api_key)
        server.register_function(self.ping)
        server.register_function(self.shutdown)
        print("[+] Registered decompilation server!")
        self.running = True
        while self.running:
            server.handle_request()
