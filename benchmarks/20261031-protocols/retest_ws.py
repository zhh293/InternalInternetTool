import suite
def save():
    (suite.P/'ws-retest.json').write_text(suite.json.dumps(suite.RESULTS,indent=2),encoding='utf-8')
    (suite.P/'ws-retest-monitor.json').write_text(suite.json.dumps(suite.MONITOR,indent=2),encoding='utf-8')
suite.save=save
sv,g,u=suite.origins.start(suite.PASSWORD)
try:
    suite.start('frp','tcp');suite.origins.TARGET=19107
    suite.measure('frp','WebSocket-64KiB-retest',1,lambda:suite.ws(n=65536),count=15)
    suite.health('frp-websocket-retest')
finally:
    suite.stop();g.stop(0);u.close()
    for s in sv:s.shutdown()
