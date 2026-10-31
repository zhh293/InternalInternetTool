import collections,json,math,pathlib,re,statistics,hashlib
p=pathlib.Path(__file__).resolve().parent
r=json.loads((p/'results.json').read_text(encoding='utf-8'));m=json.loads((p/'monitor.json').read_text(encoding='utf-8'))
names={'java':'自建 Java/Netty','frp':'frp 0.71.1','openssh':'OpenSSH 8.9p1'}
groups=collections.defaultdict(list)
for x in r:groups[(x['tool'],x['size'],x['concurrency'],x['keepalive'])].append(x)
lines=['# 内网穿透公网性能比较报告','', '测试日期：2026-10-31（Asia/Shanghai）。目标服务器：113.44.228.133；公网测试入口：TCP 9090。','', '## 结论与适用范围','', '本次完成自建 Java/Netty 隧道、免费开源 frp、免费 OpenSSH 反向转发的受控公网比较。测试请求从 Windows 发往服务器公网 9090，目标 HTTP 服务和隧道客户端均在 Windows，数据实际跨公网往返。以下数据反映当前网络、资源限额与配置下的表现，不能解释为软件极限性能或商用 SLA。','', '## 环境、拓扑与公平性','', '- 服务端：Ubuntu 22.04，Linux 5.15，KVM，1 vCPU，956 MiB 内存，无 swap；测试前负载接近零。服务端 Java 17.0.20.1，Windows Java 11.0.24。','- 自建程序由当前源码使用 javac --release 11 重新编译，更新已有依赖完整 JAR；SHA-256：`'+hashlib.sha256((p/'tunnel-current.jar').read_bytes()).hexdigest()+'`。','- 服务端隧道进程逐个启动，统一 MemoryMax=230 MiB、CPUQuota=60%、TasksMax=96、Nice=10、RuntimeMaxSec=900 秒。Java Xmx64 MiB、直接内存24 MiB、SerialGC、一个 Netty I/O 线程。','- Java 与 frp 均使用 TCP 多路复用、TLS、同一测试证书和单条数据通道；Java muxPoolSize=1、udpMuxPoolSize=0、默认 latency 刷新；frp tcpMux=true。','- 只使用公网9090作为被测入口。控制/工作端口仅监听服务器回环，通过 Windows 发起的 SSH -L 接入。OpenSSH 对比使用独立 sshd 和 SSH -R，不修改系统22端口服务配置。','', '```text','Windows 压测器 -> 公网113.44.228.133:9090 -> Linux 隧道服务端','                                      -> SSH承载的加密数据通道','                                      -> Windows 隧道客户端 -> Windows HTTP目标','```','', '这是真实公网端到端测试。由于没有额外开放控制/数据端口，SSH 为共同承载层；TLS-over-SSH 与 SSH-over-SSH 会增加加密、复用及 TCP 队头阻塞影响。SSH 承载进程本身不在230 MiB/60%服务限额内，所以这些限额不是整台机器或整条链路的总用量。OpenSSH 协议和多路复用方式也与其他两者不同。','', '## 测试方法','', '- HTTP/1.1；响应体为按长度固定种子的伪随机字节，逐字节校验状态码和完整响应体。关闭缓存，没有使用压缩。','- 预热5次后，每个工具顺序执行相同的6组场景，各重复3轮，最大并发4。超时12秒。每组后读取服务器内存、负载、进程RSS及服务CPU累计时间；MemAvailable低于150 MiB停止。该检查为组间检查，cgroup承担组内内存硬限制。','- 64 B短连接：1并发，每轮15次，间隔下限100 ms；64 B长连接：1并发20次、间隔100 ms，4并发每线程15次、间隔200 ms。','- 64 KiB长连接：1并发12次、间隔200 ms；4并发每线程8次、间隔400 ms。1 MiB长连接：1并发每轮3次、间隔500 ms。间隔以每次请求开始为基准，请求耗时更长时不额外等待。','- 延迟从发起HTTP请求到完整读取响应计时；短连接包括TCP建立。分位数使用最近秩法。报告表格显示三轮各自统计量的中位数，失败数求和。','- 观测Mbps=成功响应体字节×8/组总墙钟时间/1,000,000，包含人为节奏等待；RPS同样包含等待。因此二者是本次负载下的观测值，不能当作最大吞吐或最大QPS。','', '## 实测结果','', '| 工具 | 响应体 | 并发 | 连接 | 请求数/错误 | p50 ms | p95 ms | 观测 RPS | 观测 Mbps |','|---|---:|---:|---|---:|---:|---:|---:|---:|']
at=lines.index('## 环境、拓扑与公平性')
lines[at:at]=['三种工具共完成1,278次请求，错误为0。1 MiB单流观测吞吐（三轮中位数）：自建5.70 Mbps、frp 5.53 Mbps、OpenSSH 7.15 Mbps；公网直连参考约5.49 Mbps。网络可能显著约束吞吐，不能据此判定软件极限性能。', '', '64 B单并发长连接p50分别为53.39、140.87、51.64 ms；短连接分别为213.71、122.10、242.27 ms。自建在本次长连接场景较快，frp短连接较快。自建采样最大RSS约99.7 MiB，frp约25.2 MiB。', '', '测试结束已停止临时服务、释放9090、清理服务器测试目录与本地临时密钥副本；最终服务器可用内存约370 MiB，SSH正常，见cleanup-health.txt。', '']
for (tool,n,c,k),xs in groups.items():
    med=lambda key:statistics.median(x[key] for x in xs)
    lines.append(f'| {names[tool]} | {n} B | {c} | '+('长' if k else '短')+f" | {sum(x['attempts'] for x in xs)}/{sum(x['errors'] for x in xs)} | {med('p50_ms'):.2f} | {med('p95_ms'):.2f} | {med('rps'):.2f} | {med('mbps'):.3f} |")
lines+=['','p95在小样本下仅是描述性统计；例如1 MiB每轮只有3次，p95即当轮最大值。未将此类数据用于宣称尾延迟SLA，也没有用p99进行排名。','', '## 资源与安全记录','', '| 工具 | 采样最大RSS MiB | 采样最小服务器MemAvailable MiB |','|---|---:|---:|']
for tool in names:
    rss=[]; avail=[]
    for x in m:
        if x['label'].startswith(tool+'-'):
            for line in x['raw'].splitlines():
                fields=line.split()
                if fields and fields[0]=='Mem:':avail.append(float(fields[-1]))
                if len(fields)>3 and fields[0].isdigit() and fields[1].isdigit() and ('java ' in line or 'frps ' in line):rss.append(int(fields[1])/1024)
    lines.append(f'| {names[tool]} | '+(f'{max(rss):.1f}' if rss else '未采样，见原始监控')+' | '+(f'{min(avail):.0f}' if avail else '—')+' |')
lines+=['', 'RSS为组间进程采样值，不是连续峰值；cgroup memory.current 与RSS口径不同。原始监控保留了服务CPU累计时间，未把ps的进程生命周期平均CPU当作压测区间CPU。未执行极限连接数、OOM、断网或故障注入。','', '## 免费工具的覆盖情况','', '| 工具 | 本次覆盖 | 限制与解释 |','|---|---|---|','| frp | 公网9090实测 | 开源免费软件；仍需自行承担服务器和带宽费用 |','| OpenSSH反向转发 | 公网9090实测 | 免费、常见基础转发方案；不是完整的HTTP隧道管理产品 |','| Cloudflare Quick Tunnel | 官方资料对照，未跑分 | 托管入口无法直接替换为本机9090；此次没有完成可比拓扑实测，不赋性能数值 |','| ngrok Free | 官方资料对照，未跑分 | 本次没有配置账户和认证，不赋性能数值 |','', 'frp官方说明TLS与tcpMux默认启用：[TLS文档](https://gofrp.org/en/docs/features/common/network/network-tls/)、[客户端配置](https://gofrp.org/en/docs/reference/client-configures/)。Cloudflare Quick Tunnel无需账户或域名，但无可用性保证、最多200个在途请求、不支持SSE：[官方说明](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)。ngrok免费套餐文档列出1 GB/月出站流量、20,000次/月HTTP请求及速率限制，套餐可能变化，应以实际账户与当日文档为准：[官方限制](https://ngrok.com/docs/pricing-limits/free-plan-limits)。上述额度不是性能跑分。','', '## 判断边界和后续建议','', '1. 三轮为每工具内部重复，工具按Java→frp→OpenSSH顺序执行，没有跨工具随机交错；公网时段差异可能影响排名。本次属于安全的探索性测评，不能作统计显著性的性能优劣证明。','2. Windows同时运行压测器、客户端和Python目标服务，HTTP服务、Windows调度、TLS、SSH共同承载层、TCP复用、云带宽及公网抖动都可能成为瓶颈。没有测UDP、上传、断线恢复、长时间稳定性、连接容量或不同地域。','3. 需要软件极限性能时，应使用独立压测机、独立内网目标机、直接开放隧道控制/数据端口，固定云带宽，并逐级提升负载至预定延迟/错误率阈值。当前小内存服务器保持低负载测试更合适。','', '## 原始数据与复现','', '- `results.json`：每组原始请求延迟、错误、耗时及指标。','- `monitor.json`、`environment.json`：资源采样与环境、产物校验值。','- `run_wan.py`：完整公网测试脚本；参数可指定 java、frp、openssh。','- `run_direct.py`、`direct-results.json`：直连公网基线，单独解释，不能与反向隧道拓扑直接计算软件开销。','- `final-health.json`：停止测试实例后的服务器健康记录。','', '复现前在测试目录提供权限收紧的connection.tmp密钥、token、测试证书、客户端/服务端配置、官方frp二进制及编译JAR。敏感凭据不属于报告公开附件。按相同限额运行 `python run_wan.py java frp openssh`；脚本追加已有结果，重新测量前应归档已有JSON。']
if (p/'direct-results.json').exists():
    d=json.loads((p/'direct-results.json').read_text());lines+=['','## 9090直连公网参考','', '该阶段目标服务临时放在服务器，测试Windows到服务器的直接下载；只有公网入口路径，没有反向隧道和Windows上行路径，属于链路参考。']
    for n in [64,1048576]:
        values=sum([x['ms'] for x in d if x['bytes']==n],[])
        lines.append(f'- {n} B，15次请求，延迟中位数 {statistics.median(values):.2f} ms；'+(f'逐请求有效速率中位数 {statistics.median(n*8/(v/1000)/1e6 for v in values):.2f} Mbps。' if n>64 else '包含每轮首个新连接。'))
summary = '''## 最终结果：各工具表现如何

**本次结果：自建隧道的长连接延迟有优势，大响应吞吐与 frp 接近；frp 的短连接和内存占用更好；OpenSSH 的大响应观测吞吐最高。针对这台约 1 GiB 内存的服务器，如果优先节省资源，我倾向选择 frp；如果主要承载持续连接，并需要继续开发现有系统，自建方案值得保留。**

### 核心成绩一览

所有延迟均为完整响应耗时，取三轮 p50 的中位数；吞吐取三轮观测值的中位数。粗体表示该项实测数值最优，代表本次场景结果。

| 比较项目 | 自建 Java/Netty | frp 0.71.1 | OpenSSH 反向转发 | 如何理解 |
|---|---:|---:|---:|---|
| 小响应长连接延迟 ↓ | 53.39 ms | 140.87 ms | **51.64 ms** | 64 B、单并发；自建接近 OpenSSH，低于 frp |
| 小响应短连接延迟 ↓ | 213.71 ms | **122.10 ms** | 242.27 ms | 64 B、单并发；频繁新建连接时 frp 更快 |
| 4 并发小响应延迟 ↓ | 71.35 ms | 117.59 ms | **67.37 ms** | 64 B、长连接；自建仍接近 OpenSSH |
| 1 MiB 单流观测吞吐 ↑ | 5.70 Mbps | 5.53 Mbps | **7.15 Mbps** | 自建与 frp 接近，OpenSSH 此次观测最高 |
| 服务端采样最大 RSS ↓ | 99.7 MiB | **25.2 MiB** | 未采样 | 自建约为 frp 的 4 倍；不能判断 OpenSSH 内存排名 |
| 成功请求 / 总请求 | **426 / 426** | **426 / 426** | **426 / 426** | 本次均无失败、无内容校验错误 |

箭头 ↓ 表示越低越好，↑ 表示越高越好。成功率仅覆盖本次短时测试。

### 每个产品的最终评价

| 产品 | 最终评价 | 本次证据支持的优势 | 主要不足或未验证项 | 选型建议 |
|---|---|---|---|---|
| **自建 Java/Netty** | **长连接表现较好，优先优化内存和短连接** | 长连接小响应延迟比 frp 低约 62%；大响应吞吐与 frp 相差约 3% | 短连接延迟比 frp 高约 75%；采样 RSS 约为 frp 的 4 倍 | 已有持续连接业务、希望继续定制开发时保留；本次无需仅因吞吐更换方案 |
| **frp** | **这台小内存服务器上的节省资源选项** | 短连接延迟在三者中最低；已采样的两款产品中内存占用最低 | 本次长连接小响应延迟高于另外两者 | 内存余量和短连接响应更重要时，优先考虑 |
| **OpenSSH 反向转发** | **基础转发对照表现较好** | 本次大响应观测吞吐最高；长连接小响应延迟最低 | 短连接延迟最高；未采样进程内存；本次只验证基础转发 | 少量固定端口的基础转发可考虑；完整产品能力需另行比较 |
| **Cloudflare Quick Tunnel** | **未实测，暂不评价性能** | 已核对官方能力与限制 | 没有可比测试数据 | 本报告不据此给出性能选型建议 |
| **ngrok Free** | **未实测，暂不评价性能** | 已核对官方免费套餐限制 | 没有可比测试数据 | 本报告不据此给出性能选型建议 |

### 对当前自建设施的判断

**这套自建设施在本次低并发公网测试中，吞吐与 frp 相近，长连接延迟更低，但需要付出更多内存，短连接也更慢。** 如果目标是继续完善它，建议先定位短连接建立耗时，并降低 JVM/Netty 常驻内存；本次结果尚未提供优先优化大流量吞吐的充分依据。

**本次不给出综合总分。** 三个工具各有胜出项目；人为加权会掩盖业务需求差异。当前能作出的选择是：节省这台服务器的内存优先看 frp，现有长连接及定制需求可继续使用自建，基础固定端口转发可考虑 OpenSSH。

### 这些结论适用于什么条件

这是从 Windows 经公网访问服务器 **9090**、再回到 Windows 目标服务的实测，三款工具轮流执行，合计 **1,278 次请求，0 错误**。测试最大并发为 4，使用共同 SSH 承载层，并对远端服务施加资源限额；工具顺序未随机交错。因此，上表属于本次配置下的场景比较，不能证明原生直连部署的极限性能、高并发容量或长期可靠性。

公网直连 1 MiB 的逐请求有效速率中位数约 **5.49 Mbps**，提示网络可能是重要约束。该基线与隧道的拓扑和速率计算口径不同，不能用两者直接计算隧道效率。

测试后已停止临时服务、释放 9090、清理服务器测试目录及本地临时密钥副本。收尾检查显示 SSH 正常，服务器可用内存约 **370 MiB**。
'''
start=lines.index('## 结论与适用范围')
end=lines.index('## 环境、拓扑与公平性')
lines[start:end]=summary.strip().splitlines()+['']
notice='> 归档复核发现Windows残留测试JVM可能干扰历史轮换阶段，11个客户端已结束、复现脚本已修正。见[评测限制与归档复核](../../docs/评测限制与归档复核.md)。本页仅为当时条件下的探索性成绩，不是严格性能排名。后续[多协议测试](../20261031-protocols/多协议测试报告.md)还发现兼容性边界。'
lines.insert(2,notice+'\n')
(p/'性能比较报告.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
(p/'最终结论.md').write_text('# 内网穿透性能比较：最终结论\n\n'+notice+'\n\n'+summary+'\n完整方法、原始成绩和限制见[性能比较报告](性能比较报告.md)。\n',encoding='utf-8')
print('report written',len(r),'groups',sum(x['attempts'] for x in r),'requests')
