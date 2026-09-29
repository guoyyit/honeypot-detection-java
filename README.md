# 蜜罐诱饵检测服务 (Honeypot Detection for Java)

基于 Spring Boot 3 / Java 17 的欺骗防御组件：在真实服务中植入**诱饵端点**与**诱饵凭据**，
任何对诱饵资源的触碰都会被可靠识别、持久化并按策略告警；健康检查、管理接口与内部定时探活
可通过豁免规则排除，且豁免命中只抑制告警、**不销毁攻击证据**。

## 构建与运行

```bash
mvn clean package
java -jar target/honeypot-detection-java-1.0-SNAPSHOT.jar \
  --honeypot.admin-token='请替换为强随机令牌' \
  --honeypot.state-file=/var/lib/honeypot/state.json
```

开发模式：`mvn spring-boot:run`

### 配置项

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `honeypot.admin-token` | `change-me-admin-token` | 管理接口静态令牌（请求头 `X-Admin-Token`），生产必须修改 |
| `honeypot.state-file` | 临时目录 | 全部状态（诱饵/事件/告警/豁免/审计）的 JSON 持久化文件，原子写入 |
| `honeypot.alert-cooldown-millis` | `60000` | 同来源+同诱饵重复通知的冷却窗口 |
| `honeypot.internal-marker` | `HONEYPOT-INTERNAL-MARKER` | 仿真响应中嵌入的可追溯内部标记前缀 |
| `honeypot.health-path` | `/healthz` | 健康检查路径，永远不产生触碰事件 |
| `honeypot.internal-probe.interval-millis` | 24h | 内部定时探活周期 |
| `honeypot.internal-probe.base-url` | 空（探活关闭） | 探活目标基址，例如 `http://127.0.0.1:8080` |

## 检测语义

- **诱饵端点 (`HTTP_ENDPOINT`)**：只有处于 `ENABLED` 状态且路径精确匹配的诱饵会返回仿真响应；
  其它未知路径一律 404。停用/删除后立即不再产生触碰事件与告警。
- **仿真响应**：状态码、`Content-Type`、响应体均可按诱饵配置；响应自动携带内部标记
  （响应头 `X-Honeypot-Trace: <marker>:<decoyId>`，响应体尾部同样注入标记），
  仿真内容完全来自配置，不包含任何真实数据。
- **诱饵凭据 (`CREDENTIAL`)**：登录请求中出现与诱饵完全一致的用户名/密码时即判定触碰，
  登录仍按失败处理（401）。正常凭据仅做一次索引查询，不写入事件、不进入告警链路。
- **触碰事件**：记录诱饵标识、来源 IP、User-Agent、请求路径、时间戳、触碰类型与豁免信息，
  在返回响应前先同步落盘；随后由单线程异步处理器转成告警。
- **豁免**：命中规则的触碰仍完整记录（`exempted=true` 及 `matchedExemptionId`），
  只是不生成/不升级告警。证据在事件接口中永久保留。

## 可靠性保证

- **并发不丢事件**：每次触碰生成全局唯一 `eventId`，写操作经读写锁串行化并原子落盘
  （临时文件 + rename），同诱饵多来源并发触碰逐条记录（测试覆盖 32 线程 × 10 次）。
- **重启不遗漏**：应用就绪后扫描所有 `processed=false` 的事件重新入队处理；
  关闭时（`@PreDestroy`）排空队列。
- **不重复告警**：事件处理按 `eventId` 幂等，已处理事件重启后不会再次通知。
- **告警去重与分级**：告警键为 `decoyId + sourceIp`；冷却窗口内的重复触碰只累加
  `touchCount`、刷新 `lastEventAt`，不重复通知；窗口结束后再次触碰才会再次通知。
  诱饵敏感度 `0/1/2` 分别映射 `INFO/WARNING/CRITICAL`，高敏感度会上调已有告警级别。

## 管理接口

所有 `/admin/**` 接口需要请求头 `X-Admin-Token`，可选 `X-Admin-Actor` 标识操作者。
管理操作（含鉴权失败、增删改豁免规则、告警确认/关闭）全部写入审计 `/admin/audits`。

### 诱饵

```bash
# 创建诱饵端点
curl -s -X POST localhost:8080/admin/decoys \
  -H "X-Admin-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "id":"decoy-admin-panel",
    "name":"fake admin panel",
    "type":"HTTP_ENDPOINT",
    "sensitivity":2,
    "path":"/internal/admin",
    "simulatedResponse":{"statusCode":200,"contentType":"text/html","body":"<html>login</html>"}
  }'

# 创建诱饵凭据（密码只在入站时使用，存储 SHA-256 哈希，永不在接口返回）
curl -s -X POST localhost:8080/admin/decoys \
  -H "X-Admin-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"id":"decoy-db","name":"backup account","type":"CREDENTIAL",
       "sensitivity":1,"decoyUsername":"backup-admin","decoyPassword":"S3cret!"}'

curl -X POST localhost:8080/admin/decoys/decoy-admin-panel/disable -H "X-Admin-Token: $TOKEN"
curl -X POST localhost:8080/admin/decoys/decoy-admin-panel/enable  -H "X-Admin-Token: $TOKEN"
curl -X DELETE localhost:8080/admin/decoys/decoy-admin-panel       -H "X-Admin-Token: $TOKEN"
curl localhost:8080/admin/decoys -H "X-Admin-Token: $TOKEN"
```

同一 `id`、同一路径或同一凭据用户名重复注册返回 `409 Conflict`。

### 豁免规则

规则字段均为可选条件，组合时按 AND 匹配：`sourceCidr`（IPv4/IPv6 CIDR 或单 IP）、
`pathPrefix`、`headerName`/`headerValue`（`headerValue` 留空表示只校验请求头存在）。

```bash
curl -X POST localhost:8080/admin/exemptions -H "X-Admin-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"office network","sourceCidr":"10.0.0.0/8","pathPrefix":"/healthz"}'

curl -X PUT    localhost:8080/admin/exemptions/{id} -H "X-Admin-Token: $TOKEN" ...
curl -X DELETE localhost:8080/admin/exemptions/{id} -H "X-Admin-Token: $TOKEN"
```

健康检查路径与 `/admin/**` 在控制器层直接放行，天然不产生触碰事件。

### 事件、告警与审计

- `GET /admin/events?decoyId=...`：触碰事件（含豁免证据）
- `GET /admin/alerts`：告警（状态 `OPEN/ACKNOWLEDGED/CLOSED`，持久化）
- `POST /admin/alerts/{id}/acknowledge`、`POST /admin/alerts/{id}/close`
- `GET /admin/audits`：管理审计

## 告警处理流程

1. 触碰事件先落盘，再异步进入告警处理器。
2. 未关闭的同键告警被升级（计数/时间/级别），冷却期内不重复通知；
   已关闭告警的再次触碰会开启新告警。
3. 默认通道 `LoggingAlertNotifier` 以 `WARN` 输出 `[HONEYPOT_ALERT]` 日志，
   可实现 `AlertNotifier` 接口接入 Webhook/邮件/IM（作为 `@Primary` Bean 覆盖默认实现）。
4. 值班人员通过管理接口确认（ACKNOWLEDGED）与关闭（CLOSED），状态变更持久化并审计。

## 测试

```bash
mvn test
```

覆盖：诱饵全生命周期与重复注册、并发触碰不丢、真实子进程重启恢复与幂等、
告警去重/冷却/分级/确认关闭、凭据诱饵检测、豁免边界（健康检查/管理接口/CIDR/请求头）。
