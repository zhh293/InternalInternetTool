import concurrent.futures as cf
import hashlib, http.client, http.server, json, math, os, pathlib, random, re, socket, statistics, subprocess, threading, time
P=pathlib.Path(__file__).resolve().parent
os.chdir(P)
HOST='113.44.228.133'
KEY=str(P/'connection.tmp')
REMOTE='/tmp/tunnel-bench-20261031'
def ssh(cmd,timeout=30):
    return subprocess.check_output(['ssh','-i',KEY,'-o','BatchMode=yes','-o','ConnectTimeout=8','root@'+HOST,cmd],timeout=timeout,text=True,encoding='utf-8',errors='replace')
def save(name,data): (P/name).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
payloads={n:random.Random(n).randbytes(n) for n in (64,65536,1048576)}
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        n=int(self.path.strip('/').split('?')[0]); b=payloads[n]
        self.send_response(200); self.send_header('Content-Length',str(n)); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(b)
    def log_message(self,*args): pass
class HTTP(http.server.ThreadingHTTPServer): daemon_threads=True
origin=HTTP(('127.0.0.1',19091),Handler)
threading.Thread(target=origin.serve_forever,daemon=True).start()
children=[]; rows=[]; monitoring=[]
def real_java():
    probe=subprocess.run(['java','-XshowSettings:properties','-version'],capture_output=True,timeout=15)
    home=re.search(r'(?m)^\s*java.home = (.+)$',probe.stderr.decode(errors='replace'))
    if probe.returncode or home is None:raise RuntimeError('Cannot resolve the real JVM')
    return str(pathlib.Path(home.group(1).strip())/'bin'/('java.exe' if os.name=='nt' else 'java'))
def launch(args,log):
    p=subprocess.Popen(args,stdout=open(log,'w'),stderr=subprocess.STDOUT); children.append(p); return p
def snap(label):
    raw=ssh("date -Is; uptime; free -m; cat /sys/fs/cgroup/system.slice/tunnel-bench.service/memory.current 2>/dev/null; systemctl show tunnel-bench -p CPUUsageNSec -p MemoryPeak -p ActiveState; ps -C java,frps -o pid,rss,pcpu,args --no-headers || true")
    monitoring.append({'time':time.time(),'label':label,'raw':raw}); save('monitor.json',monitoring)
    avail=int(ssh("awk '/MemAvailable/ {print $2}' /proc/meminfo").strip())
    if avail<150*1024: raise RuntimeError('Safety stop: MemAvailable < 150 MiB')
def stop():
    for p in children:
        if p.poll() is None: p.terminate()
    for p in children:
        try:p.wait(timeout=8)
        except subprocess.TimeoutExpired:p.kill()
    children.clear()
    ssh('systemctl stop tunnel-bench.service || true')
def request(host,port,n,conn=None):
    c=conn or http.client.HTTPConnection(host,port,timeout=12)
    t=time.perf_counter(); c.request('GET','/'+str(n)); r=c.getresponse(); b=r.read()
    if r.status!=200 or b!=payloads[n]: raise ValueError('response integrity failure')
    elapsed=(time.perf_counter()-t)*1000
    if conn is None:c.close()
    return elapsed
def trial(tool,host,port,n,concurrency,repeat,keep,count,interval):
    def worker(k):
        c=http.client.HTTPConnection(host,port,timeout=12) if keep else None
        out=[]
        for i in range(count):
            due=time.perf_counter()+interval
            try:out.append({'ms':request(host,port,n,c),'ok':True})
            except Exception as e:
                out.append({'ok':False,'error':str(e)})
                if c:c.close()
            time.sleep(max(0,due-time.perf_counter()))
        if c:c.close()
        return out
    start=time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=concurrency) as pool: samples=sum(list(pool.map(worker,range(concurrency))),[])
    elapsed=time.perf_counter()-start; good=sorted(x['ms'] for x in samples if x['ok'])
    q=lambda p:good[min(len(good)-1,math.ceil(len(good)*p)-1)] if good else None
    row=dict(tool=tool,size=n,concurrency=concurrency,repeat=repeat,keepalive=keep,seconds=elapsed,attempts=len(samples),errors=len(samples)-len(good),p50_ms=q(.5),p95_ms=q(.95),p99_ms=q(.99),rps=len(good)/elapsed,mbps=len(good)*n*8/elapsed/1e6,samples=samples)
    rows.append(row);save('results.json',rows)
    print(json.dumps({k:v for k,v in row.items() if k!='samples'}),flush=True)
def run_tool(tool):
    stop()
    if tool=='java':
        cmd='java -Xms16m -Xmx64m -XX:MaxDirectMemorySize=24m -XX:ActiveProcessorCount=1 -XX:+UseSerialGC -Dio.netty.eventLoopThreads=1 -cp tunnel.jar dev.tunnel.Server server.properties'
    elif tool=='frp':cmd=REMOTE+'/frp_0.71.1_linux_amd64/frps -c frps.toml'
    else:cmd='/usr/sbin/sshd -D -e -p 17002 -o ListenAddress=127.0.0.1 -o GatewayPorts=clientspecified -o PidFile='+REMOTE+'/sshd.pid'
    ssh('systemd-run --unit=tunnel-bench --collect -p WorkingDirectory='+REMOTE+' -p MemoryMax=230M -p CPUQuota=60% -p TasksMax=96 -p RuntimeMaxSec=900 -p Nice=10 '+cmd)
    time.sleep(2)
    launch(['ssh','-i',KEY,'-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=10','-N','-L','17000:127.0.0.1:17000','-L','17001:127.0.0.1:17001','-L','17002:127.0.0.1:17002','root@'+HOST],tool+'-ssh.log')
    time.sleep(2)
    if tool=='java': launch([real_java(),'-Xmx128m','-XX:ActiveProcessorCount=2','-cp','tunnel-current.jar','dev.tunnel.Client','client.properties'],'java-client.log')
    elif tool=='frp': launch([str(P/'frp_0.71.1_windows_amd64'/'frpc.exe'),'-c','frpc.toml'],'frp-client.log')
    else: launch(['ssh','-i',KEY,'-p','17002','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(P/'bench-known-hosts'),'-o','ExitOnForwardFailure=yes','-N','-R','0.0.0.0:9090:127.0.0.1:19091','root@127.0.0.1'],'openssh-client.log')
    for _ in range(20):
        try:request(HOST,9090,64);break
        except Exception:time.sleep(1)
    else:raise RuntimeError(tool+' WAN readiness failed')
    snap(tool+'-ready')
    for _ in range(5):request(HOST,9090,64)
    for repeat in range(1,4):
        for n,c,keep,count,interval in [(64,1,False,15,.1),(64,1,True,20,.1),(64,4,True,15,.2),(65536,1,True,12,.2),(65536,4,True,8,.4),(1048576,1,True,3,.5)]:
            trial(tool,HOST,9090,n,c,repeat,keep,count,interval);snap(tool+'-'+str(repeat)+'-'+str(n)+'-'+str(c))
try:
    save('environment.json',{'remote':ssh('uname -a; lscpu; free -m; df -h /; java -version 2>&1; date -Is'),'local':subprocess.check_output(['java','-version'],stderr=subprocess.STDOUT,text=True),'jar_sha256':hashlib.sha256((P/'tunnel-current.jar').read_bytes()).hexdigest(),'topology':'Windows load -> public:9090 -> Linux relay -> SSH-forwarded TLS -> Windows client -> Windows origin','limits':'remote service CPU60%, memory230MiB, runtime900s; safety MemAvailable150MiB; at most4 connections; timeout12s'})
    import sys
    if (P/'results.json').exists(): rows[:]=json.loads((P/'results.json').read_text(encoding='utf-8'))
    if (P/'monitor.json').exists(): monitoring[:]=json.loads((P/'monitor.json').read_text(encoding='utf-8'))
    for tool in (sys.argv[1:] or ['java','frp','openssh']):run_tool(tool)
finally:
    stop();origin.shutdown();save('final-health.json',{'raw':ssh('uptime; free -m; ss -lntp; systemctl show tunnel-bench -p ActiveState 2>/dev/null || true')})
