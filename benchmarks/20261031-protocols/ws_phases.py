"""Separate WebSocket exchange latency from close/transport teardown waiting."""
import suite
rows=[];suite.save=lambda:None
sv,g,u=suite.origins.start(suite.PASSWORD)
try:
    for tool in ['java','frp','openssh']:
        suite.start(tool,'tcp')
        for tls,port in [(False,19107),(True,19108)]:
            suite.origins.TARGET=port
            for rep in range(3):
                row={'tool':tool,'tls':tls,'repeat':rep+1};c=None;t=suite.time.perf_counter()
                try:
                    kw={'ssl':suite.context()} if tls else {}
                    c=suite.connect(('wss' if tls else 'ws')+'://'+suite.HOST+':9090',open_timeout=8,close_timeout=2,compression=None,ping_interval=None,proxy=None,**kw)
                    row['connect_ms']=(suite.time.perf_counter()-t)*1000;t=suite.time.perf_counter();b=suite.origins.PAYLOAD[:64];c.send(b);assert c.recv(timeout=8)==b
                    row['echo_ms']=(suite.time.perf_counter()-t)*1000;t=suite.time.perf_counter();assert c.ping().wait(8);row['ping_ms']=(suite.time.perf_counter()-t)*1000
                    t=suite.time.perf_counter();c.close();row['close_ms']=(suite.time.perf_counter()-t)*1000;row['close_code']=c.close_code;row['close_reason']=c.close_reason;row['ok']=True
                except Exception as e:row.update(ok=False,error=type(e).__name__+': '+str(e))
                finally:
                    if c:c.close()
                rows.append(row);(suite.P/'ws-phases.json').write_text(suite.json.dumps(rows,indent=2));print(row,flush=True)
finally:
    suite.stop();g.stop(0);u.close()
    for s in sv:s.shutdown()
