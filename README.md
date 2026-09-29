# Honeypot Detection（诱饵与欺骗防御）

面向公网部署服务的诱饵（Honeypot）检测能力：在系统中植入**诱饵端点**与**诱饵凭据**，
任何对诱饵资源的触碰都会被可靠识别、持久化并分级告警，同时通过可配置豁免规则
保证健康检查、管理接口与内部定时任务等正常流量不产生误报。

## 快速开始

```bash
# 构建并运行测试
mvn test

# 启动服务（默认端口 8080）
mvn spring-boot:run

# 或以指定配置启动
mvn spring-boot:run -Dspring-boot.run.arguments="\
  --honeypot.data-dir=/var/lib/honeypot \
  --honeypot.admin-token=<强随机令牌> \
  --honeypot.alert-cooldown-millis=300000"
```

## 配置项

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `honeypot.data-dir` | `./honeypot-data` | 持久化目录（诱饵、事件、告警、豁免、审计） |
| `honeypot.admin-token` | `change-me` | 管理接口令牌，**生产环境必须修改** |
| `honeypot.alert-cooldown-millis` | `300000` | 告警去重冷却窗口（毫秒） |
| `honeypot.admin-path-prefix` | `/api/honeypot` | 管理接口路径前缀，诱饵不得占用 |
| `honeypot.legit-users.<name>` | 无 | 演示登录接口的合法用户（用户名→密码） |

持久化文件（位于 `data-dir`，进程重启后自动恢复）：

- `decoys.json`：诱饵端点与诱饵凭据注册表
- `touch-events.jsonl`：触碰事件追加日志（先落盘后处理，重启不丢）
- `processed-events.txt`：已处理事件 id（幂等保证，重复处理不产生重复告警）
- `alerts.json`：告警及其确认/关闭状态
- `exemptions.json`：豁免规则
- `audit.jsonl`：管理操作审计日志

## 检测语义

### 诱饵端点

- 通过管理接口注册路径（如 `/internal/debug-info`）。注册后，任何对该路径的请求都会：
  1. 生成触碰事件（先持久化，再异步处理）；
  2. 返回**仿真响应**——状态码、Content-Type、内容均可按诱饵配置；
  3. 仿真内容自动注入可追溯内部标记（JSON 注入 `_trace` 字段，HTML 追加注释），
     标记格式为 `hp:<decoyId>:<eventId>`，不含任何真实数据。
- 停用（disable）或删除后的诱饵不再产生触碰事件，请求按普通 404 处理。
- 同一 id、同一路径不得重复注册（返回 409）。
- 请求来源 IP 优先取 `X-Forwarded-For` 首跳（适用于反向代理后部署），否则取对端地址。

### 诱饵凭据

- 认证路径（演示接口 `POST /api/auth/login`）中，只要出现已注册的诱饵用户名，
  **无论认证成功与否**都会生成触碰事件，并记录口令是否命中。
- 检测为哈希表 O(1) 查找且永不抛出异常，不会拖慢或干扰正常用户认证。

### 触碰事件处理

- 事件先写入 `touch-events.jsonl` 再进入处理队列：并发触碰不丢失，进程重启后
  未处理事件自动恢复处理。
- 事件处理幂等：已处理事件 id 持久化记录，重复处理同一事件不会产生重复告警。

### 告警去重与分级

- 去重键为 `(诱饵, 来源)`：冷却窗口内的重复触碰只升级已有告警
  （`touchCount` 累加、刷新 `lastTouchAt`），不重复通知；窗口外再次触碰会重新通知。
- 告警级别由诱饵敏感度决定：`LOW→INFO`、`MEDIUM→WARNING`、`HIGH→CRITICAL`。
- 告警确认（acknowledge）与关闭（close）状态持久化，重启后保留；
  关闭后同一来源再次触碰会产生新告警。

### 豁免（防误报）

- 豁免规则类型：`SOURCE_IP_PREFIX`（来源 IP 前缀，如健康检查探针网段）、
  `PATH_PREFIX`（路径前缀）、`USER_AGENT_PREFIX`（UA 前缀，如内部定时任务标识）。
- 命中豁免的触碰**仍完整落盘**（`exempted=true` 并记录命中规则 id）作为证据，
  仅跳过告警——豁免不会吞掉真实攻击事件的证据。
- 豁免规则的增删改均记录审计。

## 管理 API

所有管理接口位于 `/api/honeypot/**`，需携带请求头 `X-Admin-Token: <令牌>`；
可选 `X-Admin-Name` 标识操作者（写入审计，默认 `admin`）。未认证返回 401。

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/honeypot/decoys/endpoints` | 创建诱饵端点（201；重复 409；非法 400） |
| `GET /api/honeypot/decoys/endpoints` | 列出诱饵端点 |
| `POST /api/honeypot/decoys/endpoints/{id}/enable` `/disable` | 启用 / 停用 |
| `DELETE /api/honeypot/decoys/endpoints/{id}` | 删除（204） |
| `POST /api/honeypot/decoys/credentials` 等 | 诱饵凭据同上 |
| `GET /api/honeypot/alerts` | 列出告警 |
| `POST /api/honeypot/alerts/{id}/acknowledge` `/close` | 确认 / 关闭告警 |
| `GET/POST/PUT/DELETE /api/honeypot/exemptions` | 豁免规则管理 |
| `GET /api/honeypot/audit` | 查询审计日志 |

创建诱饵端点示例：

```bash
curl -X POST http://localhost:8080/api/honeypot/decoys/endpoints \
  -H 'X-Admin-Token: <令牌>' -H 'X-Admin-Name: ops' \
  -H 'Content-Type: application/json' \
  -d '{
        "path": "/internal/debug-info",
        "sensitivity": "HIGH",
        "responseStatus": 200,
        "contentType": "application/json",
        "responseBody": "{\"version\":\"1.2.3\",\"status\":\"ok\"}"
      }'
```

## 告警处理流程

1. **产生**：触碰事件经去重判断后生成/升级告警，默认通过 `LoggingAlertNotifier`
   输出 `HONEYPOT-ALERT` 日志（可实现 `AlertNotifier` 接口接入 Webhook/SIEM）。
2. **研判**：`GET /api/honeypot/alerts` 查看告警（级别、来源、触碰次数、首末次时间）；
   结合 `touch-events.jsonl` 中的事件与仿真响应标记 `hp:<decoyId>:<eventId>` 追溯。
3. **确认**：`POST /api/honeypot/alerts/{id}/acknowledge`，状态持久化为 `ACKNOWLEDGED`。
4. **关闭**：处置完成后 `POST /api/honeypot/alerts/{id}/close`；关闭后同一来源
   再次触碰将产生新告警。

## 测试

```bash
mvn test
```

覆盖范围（39 个用例）：

- `DecoyLifecycleTests`：诱饵全生命周期、重复注册、管理鉴权、审计、仿真响应标记、正常流量无影响
- `ConcurrentTouchTests`：8 来源 × 8 并发触碰，事件零丢失、按源去重、通知不重复
- `RestartRecoveryTest`：未处理事件重启恢复、幂等不重复告警、注册表重载
- `AlertServiceTest`：冷却窗口去重、分级映射、确认/关闭持久化
- `ExemptionTests`：豁免命中保留证据不告警、规则增删改审计、删除后恢复告警
- `DecoyCredentialTests`：凭据对错均产生事件、停用后不产生、正常认证无干扰
- `SimulatedResponseRendererTest`：JSON/HTML/文本响应的内部标记

## 工程说明

- 纯文件持久化（JSON/JSONL），无外部依赖；多实例部署时应将 `data-dir`
  指向共享存储或按实例隔离（事件按实例处理）。
- 诱饵路径不得占用 `honeypot.admin-path-prefix` 前缀，注册时校验；
  也不要与真实业务路径冲突（过滤器会优先拦截已注册诱饵路径）。
