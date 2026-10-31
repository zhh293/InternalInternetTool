# 多协议测试产物

最终比较见[多协议测试报告](多协议测试报告.md)。此目录与首轮HTTP性能测试分离，不覆盖旧原始数据。

## 复现

1. 在本目录的`deps`安装`requirements.txt`；使用与依赖二进制匹配的Python版本，原运行解释器见`environment.json`。
2. 准备仅当前用户可访问的`connection.tmp`、短期测试`cert.pem`/`key.pem`、`token`。证书SAN包括localhost、bench.test、127.0.0.1、服务器IP。
3. 在`/tmp/tunnel-protocols-20261031`准备证书、`tunnel-current.jar`和frp Linux端。JAR引用相邻`../20261031/tunnel-current.jar`的实际被测产物。frp第三方缓存不归档，请从官方v0.71.1 Release取得Linux和Windows包，把Linux目录解压到服务器临时目录、Windows目录解压到相邻`../20261031/frp_0.71.1_windows_amd64`。Linux原下载包SHA-256为`1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803`。
4. 依次运行`python suite.py common`、`python fixture_control.py`、`python suite.py extra`、`python retest_ws.py`；同一时刻只运行一个服务实例。完整复核还包括`retests.py`、`udp_empty_control.py`、`udp_isolated.py`、`ws_phases.py`。`halfclose_control.py`和`udp_fixture_control.py`需要对应的Windows目标服务正在运行，详见各脚本说明。
5. 运行`python report.py`重建报告。

脚本会追加results.json与monitor.json，重新跑完整实验前先归档它们，避免混入重复数据。生成的配置会包含临时令牌，清理后不保留有效凭据。主机私钥和登录密钥不属于交付附件。

## 数据口径

- 正式TCP共同矩阵：19项用例×3轮×3款工具=171组；每组5次，SSH/SFTP每组3次。
- 原生UDP、HTTP/HTTPS路由：仅Java/frp，不适用于OpenSSH -R。
- fixture-control.json是无隧道的目标服务校验，不计入公网成绩。
- ws-retest.json独立记录偶发WebSocket失败的复测，不覆盖正式矩阵。
- harness-preflight-*.json含已修正的测试脚本问题，不计入成绩。

测试结束需停止`tunnel-protocols.service`，清理服务器独立临时目录、本地connection.tmp、key.pem和token；保留报告、公开证书、配置模板和原始数据。

历史公开证书没有配套私钥；复测必须重新生成测试证书并更新两端文件。脚本中的IP、目录和端口是原实验参数，应先替换为自己的环境。归档清单及只读校验命令见[评测总览](../README.md)。
