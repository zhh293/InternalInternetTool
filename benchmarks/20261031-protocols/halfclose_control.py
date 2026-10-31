"""Run against the same local fixture while the WAN suite is running."""
import socket, pathlib, json, struct, time
p=pathlib.Path(__file__).resolve().parent
rows=[]
for port in [19103]:
    for i in range(5):
        with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
            s.settimeout(3);t=time.perf_counter();b=bytes(range(64));s.sendall(b'H'+b);s.shutdown(socket.SHUT_WR);out=b''
            while len(out)<len(b):
                d=s.recv(1024)
                if not d:break
                out+=d
            rows.append({'port':port,'ok':out==b,'ms':(time.perf_counter()-t)*1000})
(p/'halfclose-control.json').write_text(json.dumps(rows,indent=2))
assert all(x['ok'] for x in rows)
print('Local fixture half-close: 5/5 passed')
