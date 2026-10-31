"""Remote loopback ingress, but reverse target remains on Windows across WAN."""
import socket,secrets,time,json,sys
rows=[]
for rep in range(1,4):
    for n in [0,64,1200,8192,65507]:
        samples=[];st=time.perf_counter()
        for i in range(5):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                s.settimeout(2);b=secrets.token_bytes(n);t=time.perf_counter()
                try:
                    s.sendto(b,('127.0.0.1',9090));out,_=s.recvfrom(65535);assert out==b
                    samples.append({'ok':True,'ms':(time.perf_counter()-t)*1000,'meta':{'verified_bytes':n}})
                except Exception as e:samples.append({'ok':False,'ms':(time.perf_counter()-t)*1000,'error':type(e).__name__+': '+str(e)})
            time.sleep(.05)
        rows.append({'case':'UDP-remote-ingress-'+str(n)+'B','repeat':rep,'samples':samples,'seconds':time.perf_counter()-st})
print(json.dumps(rows))
