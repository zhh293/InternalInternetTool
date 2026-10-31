"""Validate exactly the same probes against fixtures without a tunnel."""
import suite
suite.HOST='127.0.0.1'
suite.health=lambda label:None
sv,g,u=suite.origins.start(suite.PASSWORD)
front=suite.origins.Server(('127.0.0.1',9090),suite.origins.Front)
suite.threading.Thread(target=front.serve_forever,daemon=True).start()
# Do not append fixture results to WAN results or replace the WAN monitor.
suite.save=lambda:None
try:
    suite.tcp_suite('fixture-control',0)
    (suite.P/'fixture-control.json').write_text(suite.json.dumps(suite.RESULTS,indent=2),encoding='utf-8')
    assert all(x['errors']==0 for x in suite.RESULTS),'Fixture validation failure'
finally:
    front.shutdown();g.stop(0);u.close()
    for s in sv:s.shutdown()
