import http.client,json,pathlib,subprocess,time,random
p=pathlib.Path(__file__).resolve().parent
key=str(p/'connection.tmp');host='113.44.228.133'
def ssh(cmd):return subprocess.check_output(['ssh','-i',key,'root@'+host,cmd],text=True)
rows=[]
try:
    ssh('systemd-run --unit=tunnel-direct --collect -p MemoryMax=80M -p CPUQuota=60% -p RuntimeMaxSec=180 /usr/bin/python3 /tmp/tunnel-bench-20261031/direct_origin.py')
    time.sleep(2)
    for rep in range(3):
        for n in [64,1048576]:
            c=http.client.HTTPConnection(host,9090,timeout=15);samples=[]
            for i in range(5):
                t=time.perf_counter();c.request('GET','/'+str(n));r=c.getresponse();b=r.read()
                assert r.status==200 and b==random.Random(n).randbytes(n)
                samples.append((time.perf_counter()-t)*1000);time.sleep(.2)
            c.close();rows.append({'repeat':rep+1,'bytes':n,'ms':samples,'transfer_mbps':[n*8/(v/1000)/1e6 for v in samples]})
    (p/'direct-results.json').write_text(json.dumps(rows,indent=2))
finally:
    ssh('systemctl stop tunnel-direct || true')
