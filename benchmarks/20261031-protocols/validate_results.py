import pathlib,json,collections,re
p=pathlib.Path(__file__).resolve().parent
def read(name):return json.loads((p/name).read_text(encoding='utf-8'))
r=read('results.json');g=collections.defaultdict(list)
for x in r:g[(x['tool'],x['case'])].append(x)
common=[x for x in r if not x['case'].startswith(('native-','UDP-'))]
assert len(common)==171
assert sum(x['attempts'] for x in common)==819
for tool in ['java','frp','openssh']:
    cases={x['case'] for x in common if x['tool']==tool};assert len(cases)==19
    for c in cases:assert sorted(x['repeat'] for x in g[(tool,c)])==[1,2,3]
assert len(r)==237 and sum(x['attempts'] for x in r)==1149
assert all(x['attempts']==len(x['samples']) and x['errors']==sum(not s['ok'] for s in x['samples']) for x in r)
assert all(x['errors']==0 for x in read('fixture-control.json'))
assert len(read('fixture-control.json'))==19
assert all(x['ok'] for x in read('halfclose-control.json'))
assert all(x['ok'] for x in read('udp-fixture-control.json'))
assert all(x['ok'] for x in read('udp-reference.json'))
assert all(x['ok'] for x in read('udp-empty-reference.json'))
cr=read('configuration-retests.json');assert len(cr)==27
assert all(x['errors']==0 for x in cr if x['case'].startswith('native-'))
assert len(read('udp-isolated.json'))==6
ph=read('ws-phases.json');assert len(ph)==18 and all(x['ok'] for x in ph)
assert all(x['errors']==0 for x in read('ws-retest.json'))
mon=read('monitor.json')+read('configuration-retests-monitor.json')
oom=[int(v) for x in mon for v in re.findall(r'(?m)^oom_kill (\d+)$',x['raw'])]
assert oom and max(oom)==0
summary={'formal_groups':len(r),'formal_operations':sum(x['attempts'] for x in r),'formal_failed_operations':sum(x['errors'] for x in r),'common_groups':len(common),'common_operations':819,'configuration_retest_operations':sum(x['attempts'] for x in cr),'ws_retest_operations':sum(x['attempts'] for x in read('ws-retest.json')),'fixture_operations':sum(x['attempts'] for x in read('fixture-control.json')),'websocket_phase_sessions':len(ph),'sampled_oom_kills':max(oom),'validation':'passed'}
(p/'validation.json').write_text(json.dumps(summary,indent=2));print(summary)
