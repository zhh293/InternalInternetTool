"""Reset frp between large-packet sizes; small probes bracket each large probe."""
import suite
rows=[]
suite.save=lambda:None
sv,g,u=suite.origins.start(suite.PASSWORD)
try:
    suite.FRP_UDP_SIZE=65535
    for n in [8192,65507]:
        suite.start('frp','udp')
        for label,size in [('before',64),('large',n),('after',64)]:
            with suite.socket.socket(suite.socket.AF_INET,suite.socket.SOCK_DGRAM) as s:
                s.settimeout(2);b=suite.secrets.token_bytes(size);t=suite.time.perf_counter()
                try:
                    s.sendto(b,(suite.HOST,9090));out,_=s.recvfrom(65535)
                    rows.append({'large_size':n,'stage':label,'bytes':size,'received_bytes':len(out),'ok':out==b,'ms':(suite.time.perf_counter()-t)*1000})
                except Exception as e:rows.append({'large_size':n,'stage':label,'bytes':size,'ok':False,'error':type(e).__name__+': '+str(e)})
            suite.time.sleep(.1)
        (suite.P/'udp-isolated.json').write_text(suite.json.dumps(rows,indent=2))
        print(rows[-3:],flush=True)
finally:
    suite.stop();g.stop(0);u.close()
    for s in sv:s.shutdown()
