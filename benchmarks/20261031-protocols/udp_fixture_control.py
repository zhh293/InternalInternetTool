import socket,pathlib,json,time
p=pathlib.Path(__file__).resolve().parent;rows=[]
for n in [0,64,1200,8192,65507]:
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(3);b=bytes(n);t=time.perf_counter();s.sendto(b,('127.0.0.1',19092));out,_=s.recvfrom(65535);rows.append({'bytes':n,'ok':out==b,'ms':(time.perf_counter()-t)*1000})
(p/'udp-fixture-control.json').write_text(json.dumps(rows,indent=2));assert all(x['ok'] for x in rows)
print('UDP fixture sizes 0..65507: all passed')
