# Java 内网穿透

这是一个用 Java 11 + Netty 实现的自部署内网穿透系统。公网服务器运行 `dev.tunnel.Server`，内网机器运行 `dev.tunnel.Client`；客户端主动连接服务器，外部用户通过服务器公开端口访问内网服务。

当前实现包含 TLS 控制连接、多条工作连接上的 TCP 多路复用与每流窗口背压、UDP 映射、HTTP/HTTPS Host/SNI 路由、动态映射存储、健康检查、负载均衡、带宽限制、独立客户端凭据、协议版本/错误码、Prometheus 指标、管理端认证、断线重连、超时、基础配额和运行态管理界面。TCP/UDP/HTTP 流量均使用带 stream-id 的长度帧，不会为每个 TCP 访问重复建立 TLS 工作连接。

## 构建

需要 JDK 11+ 与 Maven：

```sh
mvn package
```

产物 `target/tunnel-0.4.0.jar` 是包含依赖的 JAR；服务端和客户端使用不同的主类启动。
`mvn test` 和 `mvn package` 会自动运行 TCP、功能和 mux 保活冒烟检查；需要跳过检查时可使用 `mvn -DskipTests package`。

## 准备配置

从 [服务端配置](config/server.properties.example) 和 [客户端配置](config/client.properties.example) 各复制一份到运行机器，并修改地址、端口及路径。令牌文件内容应是双方一致的随机字符串，至少 24 个非空白字符。配置文件使用 Java `.properties` 语法；`map.<名称>=<公网端口>,<内网地址>,<内网端口>` 可以写多条。

服务端需要 PEM 格式的服务器证书和私钥，客户端的 `caFile` 需要信任签发服务器证书的 CA。测试时可以把自签名服务器证书本身作为 `caFile`；正式使用应为服务器域名配置有效的 SAN，并限制私钥与令牌文件的读取权限。服务端会在控制端口、工作端口、可选 HTTP 端口及每条 TCP/UDP 映射端口监听；默认管理 API 只绑定 `127.0.0.1:8088`。

```sh
java -cp target/tunnel-0.4.0.jar dev.tunnel.Server server.properties
java -cp target/tunnel-0.4.0.jar dev.tunnel.Client client.properties
```

示例把 `server:22022` 映射到客户端的 `127.0.0.1:22`。外部访问者使用 `ssh -p 22022 user@server`。UDP 使用 `udp.<名称>=公网端口,内网地址,内网端口`，HTTP 使用 `http.<名称>=域名|别名,内网地址,内网端口`，并让请求访问服务端的 `httpPort`。服务器防火墙和云安全组需要放行控制端口、工作端口、HTTP 端口与公开端口；客户端只需能够主动连接服务器。

打开 `http://127.0.0.1:8088/` 可以查看客户端、映射和活动流；`GET /api/status` 返回 JSON，`GET /metrics` 返回 Prometheus 指标，`POST /api/clients/<clientId>/disconnect` 可断开指定客户端，`/api/clients/<clientId>/bindings` 支持动态映射增删查。配置 `managementTokenFile` 后，API 使用 `Authorization: Bearer <token>`；管理端口应通过防火墙或反向代理限制来源。

## 验证

项目包含真实 TCP/TLS 集成测试 [Smoke.java](src/test/java/dev/tunnel/Smoke.java)。它验证小块二进制、1 MiB 往返、并发短连接和客户端重启恢复。测试会自行生成临时证书和配置，并选择空闲的本地端口，无须使用生产配置。`mvn test` 会执行 TCP、功能和 mux 保活冒烟检查；`mvn package` 也会执行它们：

```sh
mvn test
```

下面手动运行的 Java 命令中，Windows classpath 分隔符为 `;`，Linux/macOS 使用 `:`。

附加边界检查会验证 408/431 响应、持久化失败回滚和 512 条 UDP 流上限：

```sh
java -cp "target/test-classes;target/tunnel-0.4.0.jar" dev.tunnel.FeatureSmoke --limits
```

公网 UDP 映射每客户端最多保留 512 个逻辑流；等待本地连接建立期间，每流最多缓存 256 KiB，每客户端最多缓存 8 MiB，超限的数据报会丢弃。HTTP 入口要求在 15 秒内收到完整请求头，头部上限为 64 KiB。管理 API 的映射表单上限为 64 KiB。`health.<name>=http,...` 会向本地目标的 `/` 发起 HTTP GET，并把 2xx/3xx 响应视为健康；需要虚拟主机名时可配置 `http.<name>.hostRewrite`。

性能基线可以运行 `PerformanceSmoke`（32 MiB 预热后重复测量 3 次，每次 256 MiB 单流吞吐，并报告进程/系统 CPU）和 `StressSmoke`（多客户端持续回环、CPU/堆采样）：

```sh
java -cp "target/test-classes;target/tunnel-0.4.0.jar" dev.tunnel.PerformanceSmoke
java -cp "target/test-classes;target/tunnel-0.4.0.jar" dev.tunnel.StressSmoke 2 2 30 2
```

`StressSmoke` 参数依次是客户端数、每客户端连接数、持续秒数和 TCP/HTTP 工作连接池 `muxPoolSize`。UDP 默认使用独立的 `udpMuxPoolSize=1` 工作连接，避免 UDP 突发排队阻塞 TCP；将两端该项都设为 `0` 可关闭隔离。压测是本机环回基线，不等价于公网 SLA；连接池大小会影响吞吐和资源占用，应结合目标机器和真实网络单独测量。

架构、协议、开发流程及后续扩展见 [开发文档.md](开发文档.md)。

## 缓冲区与刷新策略

TCP/UDP 数据面使用引用计数 `ByteBuf`、保留切片和 `CompositeByteBuf` 组合帧头与数据体，避免原来的 `ByteBuf → byte[] → ByteBuf` 中间复制。解码后的数据直接保留切片交给目标连接；待发送队列在发送或关闭时释放引用。TLS 加密仍需生成密文，这不是端到端零拷贝。HTTP/HTTPS 只重建需要改写的请求头，首包请求体用组合缓冲区保留，后续数据直接切片转发；等待内网连接建立时收到的数据也会有界排队。UDP 入口与出口都按完整报文收发，接收缓冲区为 64 KiB；批次中不超过 256 字节的小报文会合并复制到 4 KiB 以下的连续块，较大的报文仍用保留切片，减少小报文的组件和分配数量。排队时每流还限制为最多 256 个报文，小报文若占着超过自身 8 倍的大缓冲区且小于 4 KiB，会紧凑复制以避免内存滞留。

服务端和客户端均可独立设置 `flushMode`：

| 配置 | 刷新行为 |
| --- | --- |
| `latency`（默认） | 当前读批次内合并 flush，读完成即刷新；没有读批次时立即刷新。 |
| `balanced` | 在上述基础上，读批次外通过 EventLoop 后续任务合并 flush；适合测量吞吐与延迟后选择。 |

两种模式都不等待固定字节数或固定毫秒数；最多累计 64 次 flush 请求即刷新，连接变为不可写时也会刷新。`balanced` 的任务调度不是硬实时延迟上限，EventLoop 繁忙仍会延迟发送。控制连接保持即时刷新，工作连接内的 ACK、CLOSE 和心跳遵循该连接的刷新策略。引用计数切片可能延长底层大缓冲区的存活时间，内存评估应包含直接内存，不能只看 JVM 堆。

TCP 连接默认启用 `tcpNoDelay=true`，避免 Nagle 算法把小块转发数据等到后续报文；如需比较延迟与吞吐，可在客户端和服务端分别设为 `false` 后压测。

当前 Netty NIO UDP 发送实现会忽略空数据报；mux 帧层保留空载荷，但不代表已端到端支持空 UDP 报文。新增验证覆盖 65,507 字节 UDP 报文、同来源混合长度报文，以及 HTTP/HTTPS 的 96 KiB 完整和分段请求体。
