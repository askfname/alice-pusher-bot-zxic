# WebUI 与 PDU 引擎重构 TODO

## 目标

- 将 `src/alice-sms-pusher.c` 重命名为 `src/webui.c`，作为 WebUI、配置、自启动、服务启停、HTTP 路由和 CLI 入口核心。
- 将 `src/alice-pusher-bot.c` 作为 PDU/strace/推送引擎核心，不再包含 `main`。
- 保持单二进制产物：继续输出 `output/alice-pusher-bot` 和 `output/alice-pusher-bot.run`。

## TODO

- [x] 新增 `src/alice-pusher-bot.h`，定义 WebUI 调用引擎的公共接口。
- [x] 将 `src/alice-sms-pusher.c` 改名为 `src/webui.c`。
- [x] 从 `webui.c` 删除重复的 PDU、strace、TLS webhook 发送实现。
- [x] 将 WebUI 当前已有的平台能力迁移到 `alice-pusher-bot.c` 引擎核心：
  - `dingtalk`
  - `feishu`
  - `wecom`
  - `bark`
  - `serverchan`
  - `discord`
  - `telegram`
  - `custom`
- [x] 在引擎核心保留目标进程选择能力：
  - `/sbin/zte_mifi`
  - `/sbin/zte_ufi`
  - 自定义绝对路径
- [x] 让 `webui.c` 通过引擎 API 启动服务、停止服务、清理 strace 子进程、读取手机号和发送测试消息。
- [x] 更新 `make.sh`，同时编译 `src/webui.c` 与 `src/alice-pusher-bot.c`。
- [x] 更新文档中仍指向旧源码名或旧入口的说明。
- [x] 运行构建和基础检查。

## 兼容要求

- 保持现有命令兼容：
  - `alice-pusher-bot -w`
  - `alice-pusher-bot --webui`
  - `alice-pusher-bot --mode=service_start ...`
  - `alice-pusher-bot --mode=send_once ...`
- 保持现有配置文件格式兼容：`/mnt/userdata/etc_rw/alice_pusher.conf`。
- 不改变输出二进制名称。

## 测试项

- [x] `sh ./make.sh` 成功生成 `output/alice-pusher-bot` 和 `output/alice-pusher-bot.run`。
- [x] 链接阶段无重复符号，重点检查 `main`、`send_webhook_msg`、`decode_pdu`、`signal_handler`。
- [ ] `output/alice-pusher-bot` 无参数时显示 usage。
- [ ] `output/alice-pusher-bot --mode=send_once` 缺参数时显示 usage。
- [x] WebUI 的启动、停止、重启、测试发送路径都调用引擎 API。

> 说明：当前构建产物是 ARM 静态二进制，无法在本机 x86 环境直接执行；CLI usage 验证需要在目标设备或 ARM 运行环境中完成。

## 已确定方案

- 采用单二进制方案。
- 保留 WebUI 当前已有的全部推送平台和自定义模板能力。
- WebUI 与引擎在同一二进制内通过 C 函数接口协作，不引入新的进程间协议。
