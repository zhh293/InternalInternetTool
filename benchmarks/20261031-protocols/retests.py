import suite
def save():
    (suite.P/'configuration-retests.json').write_text(suite.json.dumps(suite.RESULTS,indent=2),encoding='utf-8')
    (suite.P/'configuration-retests-monitor.json').write_text(suite.json.dumps(suite.MONITOR,indent=2),encoding='utf-8')
suite.save=save
(suite.P/'configuration-retests-settings.json').write_text(suite.json.dumps({'frp_udpPacketSize':65535,'route_readiness':'valid HTTP response before measurement','original_default_udpPacketSize':1500},indent=2))
sv,g,u=suite.origins.start(suite.PASSWORD)
try:
    suite.FRP_UDP_SIZE=65535;suite.start('frp','udp');suite.udp_suite('frp')
    # Recheck route GETs after explicitly waiting for registration, preserving initial 404s.
    for tool in ['java','frp']:
        for mode in ['http','https']:
            suite.start(tool,mode)
            for rep in range(1,4):suite.measure(tool,'native-'+mode+'-route-ready',rep,lambda mode=mode:suite.http(tls=mode=='https',hostroute=True),count=5)
finally:
    suite.stop();g.stop(0);u.close()
    for s in sv:s.shutdown()
