"""Run bounded end-to-end probes through public :9090. Never imports old benchmarks."""
import sys,pathlib
P=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(P/'deps'))
import concurrent.futures, hashlib, http.client as httplib, io, json, math, os, re, secrets, socket, ssl, statistics, struct, subprocess, threading, time
import grpc,paramiko,h2.config,h2.connection,h2.events
from websockets.sync.client import connect
import origins
os.chdir(P)
HOST='113.44.228.133';REMOTE='/tmp/tunnel-protocols-20261031';KEY=str(P/'connection.tmp');OLD=P.parent/'20261031'
UNIT='tunnel-protocols';CHILDREN=[];RESULTS=[];MONITOR=[];PASSWORD=secrets.token_hex(20);FRP_UDP_SIZE=None
def ssh(cmd,timeout=35):
    return subprocess.check_output(['ssh','-i',KEY,'-o','BatchMode=yes','-o','ConnectTimeout=10','root@'+HOST,cmd],timeout=timeout,text=True,encoding='utf-8',errors='replace')
def scp(*files):subprocess.check_call(['scp','-i',KEY,*map(str,files),'root@'+HOST+':'+REMOTE+'/'],timeout=60)
def save():
    (P/'results.json').write_text(json.dumps(RESULTS,ensure_ascii=False,indent=2),encoding='utf-8')
    (P/'monitor.json').write_text(json.dumps(MONITOR,ensure_ascii=False,indent=2),encoding='utf-8')
def health(label):
    raw=ssh('date -Is; uptime; free -m; systemctl show '+UNIT+' -p ActiveState -p CPUUsageNSec; cat /sys/fs/cgroup/system.slice/'+UNIT+'.service/memory.current /sys/fs/cgroup/system.slice/'+UNIT+'.service/memory.events /sys/fs/cgroup/system.slice/'+UNIT+'.service/cpu.stat 2>/dev/null; ps -C java,frps,sshd -o pid,rss,args --no-headers; ss -lntup')
    MONITOR.append({'label':label,'time':time.time(),'raw':raw});save()
    if int(ssh("awk '/MemAvailable/{print $2}' /proc/meminfo"))<150*1024:raise RuntimeError('Safety stop: available memory <150MiB')
def launch(args,label):
    p=subprocess.Popen(args,stdout=open(P/(label+'.log'),'a',encoding='utf-8'),stderr=subprocess.STDOUT);CHILDREN.append(p);return p
def real_java():
    probe=subprocess.run(['java','-XshowSettings:properties','-version'],capture_output=True,timeout=15)
    home=re.search(r'(?m)^\s*java.home = (.+)$',probe.stderr.decode(errors='replace'))
    if probe.returncode or home is None:raise RuntimeError('Cannot resolve the real JVM')
    return str(pathlib.Path(home.group(1).strip())/'bin'/('java.exe' if os.name=='nt' else 'java'))
def stop():
    for p in CHILDREN:
        if p.poll() is None:p.terminate()
    for p in CHILDREN:
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill()
    CHILDREN.clear();ssh('systemctl stop '+UNIT+'.service 2>/dev/null || true');time.sleep(.5)
def configure(tool,mode):
    token=secrets.token_hex(24);(P/'token').write_text(token)
    server='bindHost=127.0.0.1\ncontrolPort=17000\nworkPort=17001\npublicBindHost=0.0.0.0\nallowedPortStart=9090\nallowedPortEnd=9090\ntokenFile=token\ncertFile=cert.pem\nkeyFile=key.pem\nmanagementPort=0\nhttpPort=0\nmuxPoolSize=1\nudpMuxPoolSize=0\nudpIoThreads=1\n'
    client='serverHost=127.0.0.1\ncontrolPort=17000\nworkPort=17001\nclientId=protocol-bench\ntokenFile=token\ncaFile=cert.pem\nmuxPoolSize=1\nudpMuxPoolSize=0\nudpIoThreads=1\n'
    fs='bindAddr="127.0.0.1"\nbindPort=17000\nproxyBindAddr="0.0.0.0"\nauth.method="token"\nauth.token="'+token+'"\ntransport.tls.force=true\ntransport.tls.certFile="cert.pem"\ntransport.tls.keyFile="key.pem"\nallowPorts=[{single=9090}]\n'
    fc='serverAddr="127.0.0.1"\nserverPort=17000\nauth.method="token"\nauth.token="'+token+'"\ntransport.tls.enable=true\ntransport.tls.trustedCaFile="cert.pem"\ntransport.tls.serverName="localhost"\ntransport.tcpMux=true\n'
    if mode=='tcp':
        client+='map.bench=9090,127.0.0.1,19091\n'
        fc+='[[proxies]]\nname="bench"\ntype="tcp"\nlocalIP="127.0.0.1"\nlocalPort=19091\nremotePort=9090\n'
    elif mode=='udp':
        client+='udp.bench=9090,127.0.0.1,19092\n'
        fc+='[[proxies]]\nname="bench"\ntype="udp"\nlocalIP="127.0.0.1"\nlocalPort=19092\nremotePort=9090\n'
        if FRP_UDP_SIZE:
            fs='udpPacketSize='+str(FRP_UDP_SIZE)+'\n'+fs;fc='udpPacketSize='+str(FRP_UDP_SIZE)+'\n'+fc
    elif mode in ('http','https'):
        client+='http.bench=bench.test,127.0.0.1,19101\n'
        if mode=='http':
            server=server.replace('httpPort=0','httpPort=9090\nhttpBindHost=0.0.0.0');fs+='vhostHTTPPort=9090\n'
        else:
            server+='httpsPort=9090\nhttpsBindHost=0.0.0.0\n';fs+='vhostHTTPSPort=9090\n'
        fc+='[[proxies]]\nname="bench"\ntype="'+mode+'"\nlocalIP="127.0.0.1"\nlocalPort='+('19101' if mode=='http' else '19102')+'\ncustomDomains=["bench.test"]\n'
    for name,data in [('server.properties',server),('client.properties',client),('frps.toml',fs),('frpc.toml',fc)]: (P/name).write_text(data)
    scp(P/'server.properties',P/'frps.toml',P/'token')
def start(tool,mode):
    stop();configure(tool,mode)
    if tool=='java':cmd='/usr/bin/java -Xms16m -Xmx64m -XX:MaxDirectMemorySize=24m -XX:ActiveProcessorCount=1 -XX:+UseSerialGC -Dio.netty.eventLoopThreads=1 -cp tunnel-current.jar dev.tunnel.Server server.properties'
    elif tool=='frp':cmd=REMOTE+'/frp_0.71.1_linux_amd64/frps -c frps.toml'
    else:cmd='/usr/sbin/sshd -D -e -p 17002 -o ListenAddress=127.0.0.1 -o GatewayPorts=clientspecified -o PidFile='+REMOTE+'/sshd.pid'
    ssh('systemd-run --unit='+UNIT+' --collect -p WorkingDirectory='+REMOTE+' -p MemoryMax=230M -p CPUQuota=60% -p TasksMax=96 -p RuntimeMaxSec=900 -p Nice=10 '+cmd)
    time.sleep(1)
    launch(['ssh','-i',KEY,'-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=10','-N','-L','17000:127.0.0.1:17000','-L','17001:127.0.0.1:17001','-L','17002:127.0.0.1:17002','root@'+HOST],tool+'-underlay')
    time.sleep(1)
    if tool=='java':launch([real_java(),'-Xmx128m','-XX:ActiveProcessorCount=2','-cp',str(OLD/'tunnel-current.jar'),'dev.tunnel.Client','client.properties'],'java-client')
    elif tool=='frp':launch([str(OLD/'frp_0.71.1_windows_amd64/frpc.exe'),'-c','frpc.toml'],'frp-client')
    else:launch(['ssh','-i',KEY,'-p','17002','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(P/'known-hosts'),'-o','ExitOnForwardFailure=yes','-N','-R','0.0.0.0:9090:127.0.0.1:19091','root@127.0.0.1'],'openssh-client')
    # Check listener locally; do not turn a blocked public UDP port into a software failure.
    for i in range(15):
        out=ssh('ss -ln'+('u' if mode=='udp' else 't')+' | tail -n +2')
        if ':9090 ' in out or ':9090\n' in out:break
        time.sleep(1)
    else:raise RuntimeError('9090 listener not ready: '+tool+'/'+mode)
    health(tool+'-'+mode+'-ready')
    if mode in ('http','https'):
        readiness=[]
        for attempt in range(20):
            try:
                http(tls=mode=='https',hostroute=True);readiness.append({'ok':True});break
            except Exception as e:readiness.append({'ok':False,'error':str(e)});time.sleep(.25)
        else:raise RuntimeError('Route did not become ready: '+tool+'/'+mode)
        f=P/'route-readiness.json';previous=json.loads(f.read_text()) if f.exists() else []
        previous.append({'tool':tool,'mode':mode,'time':time.time(),'probes':readiness});f.write_text(json.dumps(previous,indent=2))
def measure(tool,name,rep,fn,count=5):
    samples=[];t=time.perf_counter()
    for i in range(count):
        st=time.perf_counter()
        try:
            meta=fn();samples.append({'ok':True,'ms':(time.perf_counter()-st)*1000,'meta':meta})
        except Exception as e:samples.append({'ok':False,'ms':(time.perf_counter()-st)*1000,'error':type(e).__name__+': '+str(e)})
        time.sleep(.05)
    elapsed=time.perf_counter()-t;good=sorted(x['ms'] for x in samples if x['ok'])
    row={'tool':tool,'case':name,'repeat':rep,'attempts':count,'errors':count-len(good),'seconds':elapsed,'p50_ms':statistics.median(good) if good else None,'max_ms':max(good) if good else None,'samples':samples}
    RESULTS.append(row);save();print(json.dumps({k:v for k,v in row.items() if k!='samples'}),flush=True)
def context(version=None,h2alpn=False):
    c=ssl.create_default_context(cafile=str(P/'cert.pem'))
    if version:c.minimum_version=version;c.maximum_version=version
    if h2alpn:c.set_alpn_protocols(['h2'])
    return c
def raw(n,half=False):
    with socket.create_connection((HOST,9090),timeout=8) as s:
        s.settimeout(8);b=origins.PAYLOAD[:n]
        s.sendall((b'H' if half else b'E'+struct.pack('!I',n))+b)
        if half:s.shutdown(socket.SHUT_WR)
        assert origins.exact(s,n)==b
        return {'verified_bytes':n,'half_close':half}
def http(tls=False,post=False,sse=False,version=None,hostroute=False):
    class NamedHTTPS(httplib.HTTPSConnection):
        def connect(self):
            self.sock=self._context.wrap_socket(socket.create_connection((HOST,9090),timeout=8),server_hostname='bench.test')
    cls=NamedHTTPS if hostroute else httplib.HTTPSConnection
    c=cls(HOST,9090,timeout=8,context=context(version)) if tls else httplib.HTTPConnection(HOST,9090,timeout=8)
    try:
        headers={'Host':'bench.test'} if hostroute else {};b=origins.PAYLOAD
        if post:c.request('POST','/echo',body=b,headers=headers)
        else:c.request('GET','/sse' if sse else '/64',headers=headers)
        r=c.getresponse();out=r.read();assert r.status==200,(r.status,out[:100]);assert out==(b if post else b'data: 0\n\ndata: 1\n\ndata: 2\n\n' if sse else b[:64])
        return {'verified_bytes':len(out),'status':r.status,'tls':c.sock.version() if tls and c.sock else None}
    finally:c.close()
def ws(tls=False,n=64):
    kw={'ssl':context()} if tls else {}
    with connect(('wss' if tls else 'ws')+'://'+HOST+':9090',open_timeout=8,close_timeout=2,compression=None,ping_interval=None,proxy=None,**kw) as c:
        b=origins.PAYLOAD[:n];c.send(b);assert c.recv(timeout=8)==b
        waiter=c.ping();assert waiter.wait(8)
        return {'verified_bytes':n,'ping_pong':True,'binary':True}
def h2probe(tls=False):
    with socket.create_connection((HOST,9090),timeout=8) as rawsock:
        s=context(h2alpn=True).wrap_socket(rawsock,server_hostname=HOST) if tls else rawsock;s.settimeout(8)
        if tls:assert s.selected_alpn_protocol()=='h2'
        h=h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True,header_encoding='utf-8'));h.initiate_connection();received={};ended=set()
        for sid in [1,3,5,7]:
            h.send_headers(sid,[(':method','GET'),(':scheme','https' if tls else 'http'),(':authority','bench.test'),(':path','/1024')],end_stream=True);received[sid]=b''
        s.sendall(h.data_to_send())
        while len(ended)<4:
            d=s.recv(65536)
            if not d:raise EOFError('HTTP/2 truncated')
            for e in h.receive_data(d):
                if isinstance(e,h2.events.ResponseReceived):assert dict(e.headers)[':status']=='200'
                if isinstance(e,h2.events.DataReceived):received[e.stream_id]+=e.data;h.acknowledge_received_data(e.flow_controlled_length,e.stream_id)
                if isinstance(e,h2.events.StreamEnded):ended.add(e.stream_id)
                if isinstance(e,h2.events.StreamReset):raise RuntimeError('RST_STREAM '+str(e.error_code))
            pending=h.data_to_send()
            if pending:s.sendall(pending)
        assert all(b==origins.PAYLOAD[:1024] for b in received.values());s.close();return {'verified_bytes':4096,'parallel_streams':4,'alpn':'h2' if tls else 'prior-knowledge'}
def grpcprobe(tls=False,stream=False,n=64):
    channel=grpc.secure_channel(HOST+':9090',grpc.ssl_channel_credentials(root_certificates=(P/'cert.pem').read_bytes()),options=(('grpc.ssl_target_name_override','localhost'),)) if tls else grpc.insecure_channel(HOST+':9090')
    try:
        b=origins.PAYLOAD[:n]
        if stream:
            out=list(channel.stream_stream('/bench.Echo/Stream')(iter([b]*3),timeout=8));assert out==[b]*3
        else:assert channel.unary_unary('/bench.Echo/Unary')(b,timeout=8)==b
        return {'verified_bytes':n*(3 if stream else 1),'messages':3 if stream else 1,'tls':tls}
    finally:channel.close()
def sshprobe(sftp=False):
    with socket.create_connection((HOST,9090),timeout=8) as sock:
        t=paramiko.Transport(sock);t.banner_timeout=8;t.auth_timeout=8
        try:
            t.start_client(timeout=8);assert t.get_remote_server_key()==origins.HOSTKEY;t.auth_password('bench',PASSWORD)
            if sftp:
                s=paramiko.SFTPClient.from_transport(t);s.get_channel().settimeout(8);b=origins.PAYLOAD
                s.putfo(io.BytesIO(b),'/bench.bin',file_size=len(b));out=io.BytesIO();s.getfo('/bench.bin',out);assert out.getvalue()==b;s.close();return {'verified_bytes':len(b)*2,'host_key_verified':True}
            ch=t.open_session(timeout=8);ch.settimeout(8);ch.exec_command('bench-echo');out=b''
            while True:
                d=ch.recv(1024)
                if not d:break
                out+=d
            assert out==b'bench-ok\n';assert ch.recv_exit_status()==0;ch.close();return {'verified_bytes':len(out),'host_key_verified':True,'exit_status':0}
        finally:t.close()
def tcp_suite(tool,rep):
    cases=[('TCP-64B',19103,lambda:raw(64)),('TCP-64KiB',19103,lambda:raw(65536)),('TCP-half-close',19103,lambda:raw(64,True)),('HTTP1-GET',19101,lambda:http()),('HTTP1-POST-64KiB',19101,lambda:http(post=True)),('SSE',19101,lambda:http(sse=True)),('HTTPS-TLS1.2',19102,lambda:http(tls=True,version=ssl.TLSVersion.TLSv1_2)),('HTTPS-TLS1.3',19102,lambda:http(tls=True,version=ssl.TLSVersion.TLSv1_3)),('WebSocket-64B',19107,lambda:ws()),('WebSocket-64KiB',19107,lambda:ws(n=65536)),('WSS',19108,lambda:ws(tls=True)),('HTTP2-h2c-4streams',19105,lambda:h2probe()),('HTTP2-TLS-4streams',19109,lambda:h2probe(True)),('gRPC-unary-64B',19106,lambda:grpcprobe()),('gRPC-unary-64KiB',19106,lambda:grpcprobe(n=65536)),('gRPC-bidirectional',19106,lambda:grpcprobe(stream=True)),('gRPC-TLS',19110,lambda:grpcprobe(tls=True)),('SSH-exec',19104,lambda:sshprobe()),('SFTP-64KiB',19104,lambda:sshprobe(True))]
    for name,port,fn in cases:
        origins.TARGET=port;measure(tool,name,rep,fn,count=3 if name in ('SSH-exec','SFTP-64KiB') else 5)
    health(tool+'-tcp-repeat'+str(rep))
def udp_suite(tool):
    ref=json.loads((P/'udp-reference.json').read_text()) if (P/'udp-reference.json').exists() else []
    if ref and not any(x['ok'] for x in ref):
        print('Public UDP reference blocked; testing remote ingress with WAN reverse leg',flush=True)
        for row in json.loads(ssh('/usr/bin/python3 '+REMOTE+'/udp_remote_probe.py',timeout=170)):
            good=[s['ms'] for s in row['samples'] if s['ok']];row.update(tool=tool,attempts=len(row['samples']),errors=len(row['samples'])-len(good),p50_ms=statistics.median(good) if good else None,max_ms=max(good) if good else None)
            RESULTS.append(row);save();print(json.dumps({k:v for k,v in row.items() if k!='samples'}),flush=True)
        health(tool+'-udp-remote-ingress-complete');return
    for rep in range(1,4):
        for n in [0,64,1200,8192,65507]:
            def probe(n=n):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                    s.settimeout(2);b=(secrets.token_bytes(16)+origins.PAYLOAD)[:n];s.sendto(b,(HOST,9090));out,_=s.recvfrom(65535);assert out==b;return {'verified_bytes':n}
            measure(tool,'UDP-'+str(n)+'B',rep,probe,count=5)
    health(tool+'-udp-complete')
def udp_reference():
    stop();scp(P/'udp_reference.py',P/'udp_remote_probe.py')
    ssh('systemd-run --unit='+UNIT+' --collect -p MemoryMax=32M -p CPUQuota=30% -p RuntimeMaxSec=30 /usr/bin/python3 '+REMOTE+'/udp_reference.py');time.sleep(1)
    rows=[]
    try:
        for i in range(3):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                s.settimeout(2);b=secrets.token_bytes(64);t=time.perf_counter()
                try:s.sendto(b,(HOST,9090));out,_=s.recvfrom(65535);rows.append({'ok':out==b,'ms':(time.perf_counter()-t)*1000})
                except Exception as e:rows.append({'ok':False,'error':type(e).__name__+': '+str(e)})
    finally:stop()
    (P/'udp-reference.json').write_text(json.dumps(rows,indent=2));print('UDP direct reference: '+json.dumps(rows),flush=True)
def main():
    global RESULTS,MONITOR
    if (P/'results.json').exists():RESULTS=json.loads((P/'results.json').read_text(encoding='utf-8'))
    if (P/'monitor.json').exists():MONITOR=json.loads((P/'monitor.json').read_text(encoding='utf-8'))
    sv,g,u=origins.start(PASSWORD)
    plan=sys.argv[1:] or ['common','extra']
    try:
        health('initial')
        (P/'environment.json').write_text(json.dumps({'remote':ssh('uname -a; java -version 2>&1; free -m; date -Is'),'python':sys.version,'versions':{'grpc':grpc.__version__,'paramiko':paramiko.__version__},'jar_sha256':hashlib.sha256((OLD/'tunnel-current.jar').read_bytes()).hexdigest(),'topology':'Windows probe -> public:9090 -> relay -> SSH-underlay -> Windows origin','limits':'service230MiB, CPU60%, Runtime900s, memory guard150MiB; each probe8s (UDP2s)'},ensure_ascii=False,indent=2),encoding='utf-8')
        if 'common' in plan:
            for rep,order in enumerate([['java','frp','openssh'],['frp','openssh','java'],['openssh','java','frp']],1):
                for tool in order:start(tool,'tcp');tcp_suite(tool,rep)
        if 'extra' in plan:
            udp_reference()
            for tool in ['java','frp']:
                start(tool,'udp');udp_suite(tool)
                for mode in ['http','https']:
                    start(tool,mode)
                    for rep in range(1,4):
                        measure(tool,'native-'+mode+'-route',rep,lambda mode=mode:http(tls=mode=='https',hostroute=True),count=5)
                        measure(tool,'native-'+mode+'-POST-64KiB',rep,lambda mode=mode:http(tls=mode=='https',hostroute=True,post=True),count=5)
                        measure(tool,'native-'+mode+'-SSE',rep,lambda mode=mode:http(tls=mode=='https',hostroute=True,sse=True),count=5)
                    health(tool+'-'+mode+'-complete')
    finally:
        stop();g.stop(0);u.close()
        for s in sv:s.shutdown()
        health('final-stopped')
if __name__=='__main__':main()
