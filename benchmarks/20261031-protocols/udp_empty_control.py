import suite
rows=[]
try:
    suite.stop();suite.ssh('systemd-run --unit='+suite.UNIT+' --collect -p MemoryMax=32M -p CPUQuota=30% -p RuntimeMaxSec=30 /usr/bin/python3 '+suite.REMOTE+'/udp_reference.py');suite.time.sleep(1)
    for i in range(3):
        with suite.socket.socket(suite.socket.AF_INET,suite.socket.SOCK_DGRAM) as s:
            s.settimeout(2);t=suite.time.perf_counter()
            try:s.sendto(b'',(suite.HOST,9090));b,_=s.recvfrom(65535);rows.append({'ok':b==b'','ms':(suite.time.perf_counter()-t)*1000})
            except Exception as e:rows.append({'ok':False,'error':str(e)})
    (suite.P/'udp-empty-reference.json').write_text(suite.json.dumps(rows,indent=2));print(rows)
finally:suite.stop()
