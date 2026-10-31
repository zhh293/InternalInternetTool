import http.server, random
data={n:random.Random(n).randbytes(n) for n in (64,65536,1048576)}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        b=data[int(self.path[1:])]
        self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def log_message(self,*args):pass
http.server.ThreadingHTTPServer(('0.0.0.0',9090),H).serve_forever()
