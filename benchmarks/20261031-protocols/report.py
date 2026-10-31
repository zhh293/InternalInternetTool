import pathlib,json,collections,statistics
P=pathlib.Path(__file__).resolve().parent
R=json.loads((P/'results.json').read_text(encoding='utf-8'))
names={'java':'自建 Java/Netty','frp':'frp 0.71.1','openssh':'OpenSSH 8.9p1'}
G=collections.defaultdict(list)
for row in R:G[(row['tool'],row['case'])].append(row)
cases=list(dict.fromkeys(row['case'] for row in R))
def cell(tool,case):
    xs=G.get((tool,case),[])
    if not xs:return '不适用 / 未测'
    total=sum(x['attempts'] for x in xs);bad=sum(x['errors'] for x in xs)
    vals=[x['p50_ms'] for x in xs if x['p50_ms'] is not None]
    status='通过' if not bad else '失败' if bad==total else '有失败'
    return f'{status} {total-bad}/{total}'+(f'；{statistics.median(vals):.1f} ms' if vals else '')
L=['# 多协议公网测试：最终结果','', '测试对象：自建 Java/Netty、frp 0.71.1、OpenSSH 8.9p1；公网服务器 113.44.228.133，入口轮流使用 9090。','', '## 先看最终结论','', '以下按实测逐项列出成功率和延迟；“通过”表示本次指定用例通过，不表示协议所有特性或长期运行均已验证。此处共同应用协议均通过TCP映射承载，原生HTTP/HTTPS路由与UDP另列。','', '| 协议 / 用例 | 自建 | frp | OpenSSH |','|---|---|---|---|']
for case in cases:L.append('| '+case+' | '+' | '.join(cell(t,case) for t in names)+' |')
L+=['','表内延迟是各轮成功样本p50的中位数，完整操作计时，包括新连接及所需握手/认证；每轮5次，SSH/SFTP每轮3次。若有失败，延迟只反映成功样本，不能用较低延迟掩盖错误。','', '## 64 KiB级操作的有效载荷速率','', '下表按每个成功操作校验的有效载荷字节×8/该操作耗时计算，再取全部成功操作中位数。它包含连接建立、握手和认证，不是持续传输上限。SFTP计算上传加下载双向总字节，其他项计算单份回显载荷，不跨协议直接排名。','', '| 场景 | 自建 Mbps | frp Mbps | OpenSSH Mbps |','|---|---:|---:|---:|']
for case in ['TCP-64KiB','HTTP1-POST-64KiB','WebSocket-64KiB','gRPC-unary-64KiB','SFTP-64KiB']:
    cells=[]
    for tool in names:
        vals=[s['meta']['verified_bytes']*8/(s['ms']/1000)/1e6 for x in G[(tool,case)] for s in x['samples'] if s['ok']]
        cells.append(f'{statistics.median(vals):.3f}' if vals else '—')
    L.append('| '+case+' | '+' | '.join(cells)+' |')
L+=['','## 各工具的结果概述','']
for tool in names:
    xs=[r for r in R if r['tool']==tool];total=sum(x['attempts'] for x in xs);bad=sum(x['errors'] for x in xs)
    fails=sorted(set(x['case'] for x in xs if x['errors']))
    common=[x for x in xs if not x['case'].startswith(('native-','UDP-'))]
    passed=sum(all(x['errors']==0 for x in G[(tool,c)]) for c in dict.fromkeys(x['case'] for x in common))
    L.append(f'- **{names[tool]}**：共同矩阵中{passed}/19项用例所有样本通过；本轮全部覆盖用例共{total}次操作、{bad}次失败。'+('需关注：'+ '、'.join(fails)+'。' if fails else '本轮未记录到失败。'))
L+=['', '## 范围与协议层次','', '- 三者的共同原生端口转发能力为TCP。OpenSSH -R没有原生UDP映射，也没有与另外两款等价的HTTP Host/SNI路由配置。未把“TCP可以承载某应用”混同为“隧道自身实现了该应用协议”。','- 共同用例覆盖：原始TCP双向完整性、发送方向半关闭、HTTP/1.1 GET/POST、有限SSE流、TLS1.2/1.3上的HTTPS、二进制WebSocket/WSS及Ping/Pong、HTTP/2明文/ALPN加密四路复用、gRPC明文/加密一元调用及双向流、SSH认证和命令、SFTP上传下载。','- “所有TCP应用协议”没有有限可枚举的全集。本轮将此前讨论的协议逐项落到19种代表用例；未覆盖FTP、数据库协议、HTTP/3/QUIC、SCP、SSH所有认证方式、WebSocket文本与扩展、HTTP/2所有流控边界，不能从代表用例推断它们已通过。','- gRPC使用官方grpcio的通用服务，消息为原始字节，双向流每次3条；HTTP/2每次4个并行逻辑流、每流1KiB。SSH使用Paramiko固定测试命令与主机密钥核验；SFTP对64KiB内存文件上传再下载并逐字节校验，未测磁盘IO。','', '## 测试路径和保护措施','', '```text','Windows请求 -> 公网9090 -> Linux隧道服务 -> SSH共同承载层','                                         -> Windows客户端 -> Windows协议目标服务','```','', '- 三轮工具顺序为Java→frp→OpenSSH、frp→OpenSSH→Java、OpenSSH→Java→frp，减轻固定顺序偏差；仍有公网抖动，未作统计显著性推断。','- 服务端硬限制230MiB内存、单核60% CPU、96个任务、最长900秒，组间检查可用内存低于150MiB停止。SSH共同承载进程不在服务cgroup内，不能把服务限额当作全机用量。','- 探测超时8秒（UDP2秒），最大HTTP/2并行流为4；负载是兼容性和低负载延迟验证，没有寻找最大QPS/吞吐，不是压力极限或长期稳定性试验。','- 每种应用的目标服务器固定为同一份Windows测试服务；所有目标只绑定回环。HTTPS/WSS校验证书与目标名称，HTTP/2 TLS核验ALPN=h2，SSH核验目标主机密钥。','- Java与frp外层TLS均启用；gRPC明文指应用层未单独启用TLS，传输路径仍有隧道TLS/SSH保护。','', '## 原生HTTP/HTTPS路由如何比较','', 'HTTP路由通过Host=bench.test验证；HTTPS通过SNI=bench.test和相同Host验证。Java的HTTPS为服务端TLS终止后转发HTTP，frp HTTPS为SNI选路后把TLS透传至目标。因此只能比较各自功能是否成功，不能用该项延迟直接评价两者实现效率。本轮SNI和Host相同，未独立验证两者不一致或缺失时的选路规则。']
if (P/'udp-reference.json').exists():
    u=json.loads((P/'udp-reference.json').read_text());ok=sum(x['ok'] for x in u)
    L+=['', '## UDP网络前提与结果解释','', f'先在服务器9090运行无隧道UDP回显参考，公网探测成功{ok}/{len(u)}次。']
    if ok==0:L+=['公网直接UDP回显也未收到响应，说明本次UDP公网路径前提不成立；没有足够证据确定是云安全组、防火墙还是路径设备过滤。未把它归为隧道软件失败。', '', '因此UDP补测采用Linux侧127.0.0.1:9090作为请求入口，目标仍为Windows UDP服务，隧道数据实际跨公网往返。表中UDP-remote-ingress只验证反向链路，**不代表公网UDP9090入口已通过**。']
    else:L+=['UDP表中结果来自Windows访问公网9090；覆盖0、64、1200、8192和65507字节数据报的回显与内容校验，未测持续高包速率、乱序率或分片丢包率。']
    L+=['UDP包含0字节空报文边界；目标Python UDP回显服务会回复空报文，若隧道未收到响应则记录超时，不能当作“0字节不需要传输”而计为成功。']
if (P/'fixture-control.json').exists():
    f=json.loads((P/'fixture-control.json').read_text());count=sum(x['attempts'] for x in f);err=sum(x['errors'] for x in f)
    L+=['', '## 测试夹具校验', '',f'同一份19项探测在无隧道的本机目标上执行，共{count}次、失败{err}次，原始记录fixture-control.json。']
if (P/'halfclose-control.json').exists():
    f=json.loads((P/'halfclose-control.json').read_text());L += [f'同一原始TCP目标的半关闭直接校验为{sum(x["ok"] for x in f)}/{len(f)}次成功，见halfclose-control.json。半关闭的含义是请求端shutdown(SHUT_WR)后继续读取目标响应，不是直接关闭整个连接。']
if (P/'ws-retest.json').exists():
    f=json.loads((P/'ws-retest.json').read_text());total=sum(x['attempts'] for x in f);bad=sum(x['errors'] for x in f)
    L+=['',f'针对frp的64KiB WebSocket另做{total}次复测，成功{total-bad}/{total}；见ws-retest.json。复测独立报告，原正式矩阵中的偶发超时仍保留，不以复测覆盖失败。']
if (P/'udp-fixture-control.json').exists():
    f=json.loads((P/'udp-fixture-control.json').read_text());L+=['',f'UDP目标直连覆盖0、64、1200、8192、65507字节，成功{sum(x["ok"] for x in f)}/{len(f)}次，见udp-fixture-control.json。']
if (P/'udp-empty-reference.json').exists():
    f=json.loads((P/'udp-empty-reference.json').read_text());L+=['',f'无隧道公网UDP空报文参考成功{sum(x["ok"] for x in f)}/{len(f)}次，见udp-empty-reference.json，用于判断空报文是否被公网路径统一丢弃。']
if (P/'configuration-retests.json').exists():
    f=json.loads((P/'configuration-retests.json').read_text());cg=collections.defaultdict(list)
    for x in f:cg[(x['tool'],x['case'])].append(x)
    L+=['', '## 配置调整与路由就绪后的复测','', 'frp官方配置说明udpPacketSize默认1500，且服务端和客户端必须一致：[客户端配置](https://gofrp.org/en/docs/reference/client-configures/)、[服务端配置](https://gofrp.org/en/docs/reference/server-configures/)。因此初始8KiB/65507B用例超出默认包长设置，不能据此判定frp协议不支持大报文。另将两端都设为65535做以下复测。','', '原生路由初始测试从监听端口出现后开始，Java首次GET在映射注册前收到404，各一次；这两次属于启动就绪过程，原始记录保留。复测增加“收到有效路由响应后再计时”的屏障，将启动过程与已就绪表现区分。','', '| 产品 | 复测场景 | 调整 | 成功 / 总数 |','|---|---|---|---:|']
    for (tool,case),xs in cg.items():
        total=sum(x['attempts'] for x in xs);bad=sum(x['errors'] for x in xs)
        L.append(f'| {names[tool]} | {case} | '+('udpPacketSize=65535' if case.startswith('UDP-') else '显式等待路由就绪')+f' | {total-bad}/{total} |')
    L+=['', '配置复测独立保存在configuration-retests.json，未覆盖原矩阵。native HTTP/HTTPS的POST和SSE原测试均在首个GET之后执行，因此不能用其全通过来证明启动阶段没有短暂404。', '', '提高包长后的frp复测在第一个8KiB报文组出现超时，客户端日志记录“message length exceed the limit”；之后的连续小报文组也超时，属于同一工作连接异常后的连带结果，不能解释为多个独立的小报文兼容性缺陷。']
if (P/'udp-isolated.json').exists():
    f=json.loads((P/'udp-isolated.json').read_text());L+=['', '### 大UDP报文隔离验证', '', '对每个大报文尺寸都重启frp测试实例，先测64B、再测大报文、再测64B；两端udpPacketSize=65535。','', '| 大报文尺寸 | 阶段 | 实测结果 |','|---:|---|---|']
    for x in f:L.append(f'| {x["large_size"]} | {x["stage"]} / {x["bytes"]}B | '+('内容校验通过' if x['ok'] else x.get('error','内容不一致'))+' |')
if (P/'ws-phases.json').exists():
    f=json.loads((P/'ws-phases.json').read_text());L+=['', '## WebSocket阶段耗时：消息与关闭分开看', '', '上文WebSocket完整操作计时包含连接、回显、Ping/Pong和关闭。关闭等待会显著影响该数值，不能把它直接当作消息往返延迟。下面另做每工具WS/WSS各3次阶段采样，仍使用2秒close_timeout，表内为阶段耗时中位数。','', '| 产品 | 模式 | 连接 ms | 64B回显 ms | Ping ms | 关闭 ms | close code |','|---|---|---:|---:|---:|---:|---|']
    for tool in names:
        for tls in [False,True]:
            xs=[x for x in f if x['tool']==tool and x['tls']==tls and x['ok']]
            if xs:L.append('| '+names[tool]+' | '+('WSS' if tls else 'WS')+' | '+' | '.join(f'{statistics.median(x[k] for x in xs):.1f}' for k in ['connect_ms','echo_ms','ping_ms','close_ms'])+' | '+','.join(str(c) for c in sorted(set(x['close_code'] for x in xs)))+' |')
    L+=['', 'close code反映WebSocket关闭状态；即使已收到正常关闭码，底层TCP结束等待仍可能接近客户端设置的关闭超时。仅凭耗时不能断言数据转发慢或完整关闭失败，需结合阶段值、关闭码和半关闭用例判断。']
L+=['','## 失败记录与判断边界','']
for (tool,case),xs in G.items():
    bad=[s['error'] for x in xs for s in x['samples'] if not s['ok']]
    if bad:L.append(f'- {names[tool]} / {case}：{len(bad)}次失败；错误类型：'+ '；'.join(sorted(set(bad)))+'。')
L+=['', '半关闭失败属于字节流结束语义边界，不能归纳为“TCP完全不可用”；偶发超时也不能单凭单次结果判断软件缺陷，需结合复测和网络状态。基础服务直连验证通过只排除了相应夹具在该条件下的错误，不能排除SSH共同承载层与公网的影响。','', '此前83/75/88分只针对首轮有限HTTP负载。本轮补测暴露的新兼容性结果应独立阅读，不沿用旧分数宣称全协议成熟度。','', '## 数据和复现','', '- results.json、monitor.json、environment.json：正式公网记录、资源采样和环境。','- suite.py、origins.py：探测器与仅回环监听的协议目标服务。','- fixture-control.json、halfclose-control.json：目标服务直接校验。','- harness-preflight-results.json：早期脚本预检，含HTTP模块命名冲突及WebSocket自动代理问题；已修正，**不纳入正式结果**。','- common.log、extra.log：执行日志；cleanup-health.txt：清理后的服务器状态。','- UDP原生与HTTP路由结果仅适用于Java和frp；OpenSSH的不适用项不按失败扣分。','', '官方能力依据：[OpenSSH -R手册](https://man.openbsd.org/ssh)、[frp TCP/UDP](https://gofrp.org/en/docs/features/tcp-udp/)、[frp HTTP/HTTPS](https://gofrp.org/en/docs/features/http-https/)。']
summary=['**最终判断：常规协议兼容性与边界语义需要分开看。** HTTPS、HTTP/2、gRPC、SSH/SFTP等常规TCP应用不能仅凭首轮HTTP跑分推断，本轮已分别发起真实协议交互。','', '| 产品 | 共同19项用例：全部样本通过的项目数 | 主要实测问题 |','|---|---:|---|']
for tool in names:
    commoncases=[c for t,c in G if t==tool and not c.startswith(('native-','UDP-'))]
    passed=sum(not any(x['errors'] for x in G[(tool,c)]) for c in commoncases)
    issues=[c for t,c in G if t==tool and any(x['errors'] for x in G[(tool,c)])]
    explanation='、'.join(issues) if issues else '本次未记录失败'
    if tool=='java':explanation='TCP半关闭、UDP空报文失败；路由启动各1次404，就绪后复测通过'
    if tool=='frp':explanation='TCP半关闭失败；WebSocket初测14/15、复测15/15；大UDP受配置和消息长度限制'
    summary.append(f'| {names[tool]} | {passed}/{len(commoncases)} | '+explanation+' |')
summary+=['', '**对自建方案的评价：** 常规协议透传已有实测支撑；TCP半关闭和UDP空报文应作为下一步兼容性排查重点。WebSocket阶段复核中，自建收到正常关闭码1000，但关闭操作约等待2秒，明显长于另外两款；消息回显与关闭耗时应分开判断。本次没有修改产品代码，也未用失败重试覆盖原始记录。上述问题均限定于本次部署和配置。','', '正式矩阵共1,149次操作、78次失败：自建/frp半关闭各15次、自建UDP空报文15次、frp默认包长下的大UDP报文30次、frp WebSocket偶发超时1次，以及Java路由启动早期404共2次。后续配置复测、隔离验证和夹具验证独立记录；不同产品覆盖项不同，不用总失败数直接排名。','']
at=L.index('| 协议 / 用例 | 自建 | frp | OpenSSH |');L[at:at]=summary
if (P/'cleanup-health.txt').exists():L+=['', '## 收尾状态', '', '测试实例已停止，服务器独立测试目录、测试令牌和私钥已清理；最终监听与内存见cleanup-health.txt。原系统SSH服务保留。资源采样中OOM kill计数均为0，数据结构与矩阵完整性校验见validation.json。']
L.insert(2,'> 归档复核发现Windows残留测试JVM可能造成资源占用和连接重试，历史轮换未完全隔离。11个客户端已结束、脚本已修正，原测量数据未回写。见[评测限制与归档复核](../../docs/评测限制与归档复核.md)。本报告只说明当时条件下的交互结果，不能作为严格性能排名。\n')
(P/'多协议测试报告.md').write_text('\n'.join(L)+'\n',encoding='utf-8')
print('Report:',len(R),'groups;',sum(x['attempts'] for x in R),'operations;',sum(x['errors'] for x in R),'errors')
