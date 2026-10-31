"""Bounded loopback-only protocol fixtures; no system services are modified."""
import concurrent.futures, io, os, pathlib, select, socket, socketserver, ssl, struct, threading, time, http.server
import grpc, paramiko
import h2.config, h2.connection, h2.events
from websockets.sync.server import serve
P=pathlib.Path(__file__).resolve().parent
PAYLOAD=bytes(range(256))*256
def exact(s,n):
    b=b''
    while len(b)<n:
        a=s.recv(n-len(b))
        if not a:raise EOFError('unexpected EOF')
        b+=a
    return b
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
class Raw(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request;s.settimeout(12)
        mode=exact(s,1)
        if mode==b'H':
            b=b''
            while True:
                d=s.recv(65536)
                if not d:break
                b+=d
                if len(b)>1048576:raise ValueError('oversize')
            s.sendall(b);return
        while True:
            try:n=struct.unpack('!I',exact(s,4))[0]
            except EOFError:return
            if n>1048576:return
            s.sendall(exact(s,n))
class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def setup(self):
        super().setup();self.connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);self.connection.settimeout(12)
    def do_GET(self):
        if self.path=='/sse':
            b=b''.join(b'data: '+str(i).encode()+b'\n\n' for i in range(3))
            self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(b)));self.end_headers()
            for line in b.splitlines(keepends=True):self.wfile.write(line);self.wfile.flush();time.sleep(.005)
        else:
            b=PAYLOAD[:int(self.path[1:])];self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def do_POST(self):
        n=int(self.headers['Content-Length']);assert n<=1048576;b=self.rfile.read(n)
        self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def log_message(self,*args):pass
class H2(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request;s.settimeout(12)
        h=h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False,header_encoding='utf-8'))
        h.initiate_connection();s.sendall(h.data_to_send())
        while True:
            d=s.recv(65536)
            if not d:return
            for e in h.receive_data(d):
                if isinstance(e,h2.events.RequestReceived):
                    path=dict(e.headers)[':path'];b=PAYLOAD[:int(path[1:])]
                    h.send_headers(e.stream_id,[(':status','200'),('content-length',str(len(b)))])
                    for j in range(0,len(b),16384):h.send_data(e.stream_id,b[j:j+16384],end_stream=j+16384>=len(b))
                if isinstance(e,h2.events.DataReceived):h.acknowledge_received_data(e.flow_controlled_length,e.stream_id)
            out=h.data_to_send()
            if out:s.sendall(out)
class Auth(paramiko.ServerInterface):
    def check_auth_password(self,u,p):return paramiko.AUTH_SUCCESSFUL if u=='bench' and p==PASSWORD else paramiko.AUTH_FAILED
    def get_allowed_auths(self,u):return 'password'
    def check_channel_request(self,kind,channel):return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self,ch,command):
        if command!=b'bench-echo':return False
        def send():
            time.sleep(.02);ch.sendall(b'bench-ok\n');ch.send_exit_status(0);ch.close()
        threading.Thread(target=send,daemon=True).start();return True
class MemoryHandle(paramiko.SFTPHandle):
    def __init__(self,store,path):super().__init__();self.store=store;self.path=path
    def read(self,offset,length):return self.store[self.path][offset:offset+length]
    def write(self,offset,data):
        if offset+len(data)>1048576:return paramiko.SFTP_FAILURE
        old=self.store[self.path];self.store[self.path]=old[:offset]+data+old[offset+len(data):];return paramiko.SFTP_OK
    def stat(self):
        a=paramiko.SFTPAttributes();a.st_size=len(self.store[self.path]);a.st_mode=0o100600;return a
class SFTP(paramiko.SFTPServerInterface):
    def __init__(self,*a,**kw):super().__init__(*a,**kw);self.store={}
    def open(self,path,flags,attr):
        if path!='/bench.bin':return paramiko.SFTP_PERMISSION_DENIED
        if flags&os.O_CREAT or flags&os.O_TRUNC:self.store[path]=b''
        if path not in self.store:return paramiko.SFTP_NO_SUCH_FILE
        return MemoryHandle(self.store,path)
    def stat(self,path):
        if path not in self.store:return paramiko.SFTP_NO_SUCH_FILE
        return MemoryHandle(self.store,path).stat()
class SSH(socketserver.BaseRequestHandler):
    def handle(self):
        t=paramiko.Transport(self.request);t.add_server_key(HOSTKEY);t.set_subsystem_handler('sftp',paramiko.SFTPServer,SFTP);t.start_server(server=Auth())
        while t.is_active():time.sleep(.1)
class Front(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection(('127.0.0.1',TARGET),timeout=12) as out:
            a=self.request;a.settimeout(12);out.settimeout(12);reads=[a,out]
            while reads:
                ready,_,_=select.select(reads,[],[],15)
                if not ready:return
                for src in ready:
                    dst=out if src is a else a;d=src.recv(65536)
                    if d:dst.sendall(d)
                    else:
                        reads.remove(src)
                        try:dst.shutdown(socket.SHUT_WR)
                        except OSError:pass
TARGET=19101;PASSWORD='';HOSTKEY=None
def start(password):
    global PASSWORD,HOSTKEY
    PASSWORD=password;HOSTKEY=paramiko.RSAKey.generate(2048)
    services=[]
    def run(server):threading.Thread(target=server.serve_forever,daemon=True).start();services.append(server)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(P/'cert.pem',P/'key.pem')
    hctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);hctx.load_cert_chain(P/'cert.pem',P/'key.pem');hctx.set_alpn_protocols(['h2'])
    run(Server(('127.0.0.1',19103),Raw));run(Server(('127.0.0.1',19104),SSH));run(Server(('127.0.0.1',19105),H2))
    plain=http.server.ThreadingHTTPServer(('127.0.0.1',19101),HTTP);plain.daemon_threads=True;run(plain)
    tls=http.server.ThreadingHTTPServer(('127.0.0.1',19102),HTTP);tls.daemon_threads=True;tls.socket=ctx.wrap_socket(tls.socket,server_side=True);run(tls)
    h2tls=Server(('127.0.0.1',19109),H2);h2tls.socket=hctx.wrap_socket(h2tls.socket,server_side=True);run(h2tls)
    def ws(c):
        for msg in c:c.send(msg)
    run(serve(ws,'127.0.0.1',19107,max_size=1048576,compression=None,ping_interval=None))
    run(serve(ws,'127.0.0.1',19108,ssl=ctx,max_size=1048576,compression=None,ping_interval=None))
    g=grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=4))
    g.add_generic_rpc_handlers((grpc.method_handlers_generic_handler('bench.Echo',{'Unary':grpc.unary_unary_rpc_method_handler(lambda b,c:b,request_deserializer=lambda b:b,response_serializer=lambda b:b),'Stream':grpc.stream_stream_rpc_method_handler(lambda it,c:it,request_deserializer=lambda b:b,response_serializer=lambda b:b)}),))
    g.add_insecure_port('127.0.0.1:19106')
    g.add_secure_port('127.0.0.1:19110',grpc.ssl_server_credentials((((P/'key.pem').read_bytes(),(P/'cert.pem').read_bytes()),)))
    g.start();run(Server(('127.0.0.1',19091),Front))
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',19092))
    def echo():
        while True:
            try:b,addr=udp.recvfrom(65535);udp.sendto(b,addr)
            except OSError:return
    threading.Thread(target=echo,daemon=True).start()
    return services,g,udp
