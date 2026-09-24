# Java 内网穿透

这是一个用 Java 11 + Netty 实现的自部署内网穿透系统。公网服务器运行 `dev.tunnel.Server`，内网机器运行 `dev.tunnel.Client`；客户端主动连接服务器，外部用户通过服务器公开端口访问内网服务。

当前实现包含 TLS 控制连接、多条工作连接上的 TCP 多路复用与背压、UDP 映射、HTTP/HTTPS Host/SNI 路由、动态映射存储、健康检查、负载均衡、带宽限制、独立客户端凭据、协议版本/错误码、Prometheus 指标、管理端认证、断线重连、超时、基础配额和运行态管理界面。TCP/UDP/HTTP 流量均使用带 stream-id 的长度帧，不会为每个 TCP 访问重复建立 TLS 工作连接。

## 构建

需要 JDK 11+ 与 Maven：

```sh
mvn package
```

产物 `target/tunnel-0.4.0.jar` 是包含依赖的 JAR；服务端和客户端使用不同的主类启动。

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

项目包含真实 TCP/TLS 集成测试 [Smoke.java](src/test/java/dev/tunnel/Smoke.java)。它验证小块二进制、1 MiB 往返、并发短连接和客户端重启恢复。测试会自行生成临时证书和配置，并选择空闲的本地端口，无须使用生产配置：

```sh
mvn package
java -cp "target/test-classes;target/tunnel-0.4.0.jar" dev.tunnel.Smoke
java -cp "target/test-classes;target/tunnel-0.4.0.jar" dev.tunnel.FeatureSmoke
java -cp "target/test-classes;target/tunnel-0.4.0.jar" dev.tunnel.MuxKeepaliveSmoke
```

Windows 的 classpath 分隔符是 `;`，Linux/macOS 使用 `:`。该测试目前需要手动执行，单独运行 `mvn test` 不会触发它。

架构、协议、开发流程及后续扩展见 [开发文档.md](开发文档.md)。
