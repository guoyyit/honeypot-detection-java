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
  仿真内容完全来自配置，不包含任何真实数据。标记嵌入方式严格跟随声明的内容类型，
  保证响应体能被调用方按响应头声明的类型**严格解析**（详见下文“标记嵌入与解析安全性”）。
- **诱饵凭据 (`CREDENTIAL`)**：登录请求中出现**已注册且处于启用状态的诱饵用户名**即判定触碰，
  与口令是否正确、认证是否成功无关；事件通过 `passwordMatched` 字段区分正确口令（`true`）
  与错误口令猜测（`false`）。认证仍一律按失败处理（401），返回行为不变。
  正常用户名仅做一次 O(1) 索引查询（哈希 Map），不计算口令哈希、不写入事件、不进入告警链路，
  额外开销不随已注册诱饵凭据数量增长。
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

## 标记嵌入与解析安全性

每个诱饵响应都同时携带两处完全一致的标记：响应头 `X-Honeypot-Trace: <marker>:<decoyId>`，
以及响应体内部的同值标记。标记含诱饵标识，管理侧可通过 `GET /admin/events?decoyId=...`
核对该标识与触碰事件、告警的关联；标记不因内容类型不同而缺失。

响应体按声明内容类型选择嵌入位置，原配置内容完整保留：

| 内容类型 | 标记嵌入位置 | 解析安全性 |
| --- | --- | --- |
| `application/json`（含 `; charset=...` 变体） | JSON 对象新增字段 `_honeypot_trace`；JSON 数组追加一个仅含该字段的对象 | 用 Jackson 重新序列化，严格 JSON；对象原有字段与数组原有元素一个不少 |
| 顶层为标量/`null` 的 JSON | 包装为 `{"value": <原值>, "_honeypot_trace": ...}` | 原值在 `value` 字段中逐字保留 |
| 配置体为空（任意 JSON 类型） | 返回 `{"_honeypot_trace": ...}` | 空体也有合法、可解析、带标记的内容 |
| 未配置内容类型 | 按 `application/json` 处理并返回该 Content-Type | 与 JSON 行相同 |
| `text/html` | 在最后一个闭合标签前插入 HTML 注释 `<!-- <marker> -->`（无闭合标签时追加到尾部）；标记内若出现非法的 `--` 会被替换为 `-` | 文档结构可被 HTML 解析器解析，注释作为 comment 节点出现 |
| `text/plain` 及其它可识别文本类型 | 响应体尾部另起一行追加标记原文 | 纯文本始终可读，配置内容位于标记之前完整保留 |
| 配置内容无法按 JSON 解析（声明为 JSON） | 降级为 `{"body": "<配置原文>", "_honeypot_trace": ...}` | 原文在 `body` 字段中逐字保留，响应仍是合法 JSON |
| 配置了无法解析/非法的 Content-Type | 响应头安全回退为 `text/plain;charset=UTF-8`，响应体按纯文本嵌入 | 不返回 5xx、不暴露异常堆栈，仍为可解析仿真内容并带标记 |

## 凭据检测的触发与事件区分

- **触发条件**：认证请求中的用户名命中任意 `ENABLED` 的 `CREDENTIAL` 诱饵即生成触碰事件，
  口令正确、口令错误、认证成功或失败均触发；事件与告警链路、冷却去重、分级、豁免语义
  与端点触碰完全一致。
- **事件区分**：凭据触碰事件带布尔字段 `passwordMatched`（端点触碰事件该字段为 `null`）。
  正确口令记为 `true`，任意错误口令记为 `false`，两类口令猜测在管理侧可直接区分。
- **认证结果**：诱饵凭据触发的认证仍返回 `401 {"error":"invalid credentials"}`，
  与普通错误凭据的响应行为完全一致。
- **停用/删除**：诱饵凭据被 disable 或 delete 后立即从用户名索引移除，
  不再产生触碰事件；正常凭据在任何数量级的诱饵注册下都只付出一次 Map 探测。
- **兼容性**：诱饵凭据注册方式、SHA-256 哈希存储形式、管理接口与持久化格式保持不变，
  旧状态文件中无 `passwordMatched` 字段的历史事件可直接加载。

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

新增覆盖：

- `ContentTypeMarkerTest`：对 `application/json`、`application/json; charset=utf-8`、
  JSON 数组、`text/html`（用 Swing HTML 解析器实际解析 DOM 与注释节点）、`text/plain`、
  空响应体、未配置 Content-Type、非法 Content-Type、声明 JSON 但内容非法共 9 种情形，
  实际按声明类型解析响应体，并逐一断言标记头与体内标记完全一致、配置内容完整保留；
  非法内容类型断言不产生 5xx 且回退为可解析的 `text/plain`。
- `CredentialDetectionTest`：覆盖诱饵用户名 + 正确口令、诱饵用户名 + 错误口令两条路径
  均产生事件且 `passwordMatched` 可区分、正常凭据不产生事件、停用/删除后不再触发、
  以及 500 个诱饵凭据注册下 200 次正常登录的单次平均耗时上限（验证开销不随诱饵数量增长）。
- `ConcurrentTouchTest`：在 32 线程 × 10 次并发触碰下，除事件逐条不丢外，
  还断言每个响应体都是合法 JSON 且体内标记与 `X-Honeypot-Trace` 头一致。

### 手动验证

```bash
# JSON 诱饵：响应体应能被 jq 严格解析，且 _honeypot_trace 与响应头一致
curl -si localhost:8080/internal/admin
curl -s localhost:8080/internal/admin | jq -e '._honeypot_trace'

# 错误口令猜测诱饵用户名：仍返回 401，但管理侧可见 passwordMatched=false 的事件
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"backup-admin","password":"wrong"}'
curl -s "localhost:8080/admin/events" -H "X-Admin-Token: $TOKEN" | jq '.[] | select(.kind=="CREDENTIAL")'
```
