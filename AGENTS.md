# AGENTS.md

## 需求背景

本项目需要在高危命令执行前接入 JumpServer 后端的人脸核验流程。KoKo 是 SSH/Telnet 等字符终端协议的核心代理组件，负责解析用户输入、识别命令、拦截高危命令、等待后端审批结果，并最终决定是否把命令发送到目标资产。

完整链路：

1. 运维人员在 KoKo 终端输入高危命令并回车。
2. KoKo 命中命令过滤 ACL 的 `review` 动作。
3. KoKo 调用 JumpServer 命令复核接口。
4. JumpServer 触发拍照系统和 AI 人脸比对。
5. 人脸比对通过后 JumpServer 创建人工审批工单。
6. KoKo 轮询工单状态。
7. 工单通过后 KoKo 放行原始命令；拒绝、关闭、超时、比对失败时禁止执行。

## 组件边界

KoKo 负责：

- 解析终端输入并识别完整命令。
- 根据连接令牌中的命令过滤 ACL 判断是否需要复核。
- 在命令执行前调用 JumpServer 命令复核接口。
- 在终端中提示“等待人脸核验/等待审批”状态。
- 轮询 JumpServer 返回的工单状态接口。
- 根据审批结果放行、拒绝或取消命令。
- 上报命令记录及风险等级。

KoKo 不负责：

- 直接调用拍照系统。
- 直接调用 AI 人脸平台。
- 保存人脸照片。
- 创建审批工单。
- 审计台前端展示。

## 涉及代码目录

主要目录：

- `pkg/proxy/parser.go`
  - 核心命令解析、命令过滤命中、复核等待和放行逻辑。
  - 现有关键方法：`IsMatchCommandRule`、`waitCommandConfirm`、`sendCommandToChan`。
- `pkg/jms-sdk-go/service/jms_ticket.go`
  - JumpServer 工单相关 API client。
  - 现有关键方法：`SubmitCommandReview`、`CheckConfirmStatusByRequestInfo`、`CancelConfirmByRequestInfo`。
- `pkg/jms-sdk-go/service/url.go`
  - JumpServer API 路径常量。
  - 现有命令复核路径：`/api/v1/acls/command-filter-acls/command-review/`。
- `pkg/jms-sdk-go/model/ticket.go`
  - 命令复核接口响应结构。
- `pkg/jms-sdk-go/model/audit_command.go`
  - 命令风险等级。
- `pkg/proxy/recorder.go`
  - 命令记录上报。
- `locale/`
  - 终端提示语翻译。

## 现有命令复核逻辑

当前 KoKo 已有命令复核流程：

1. `Parser.parseInputState` 收到用户输入。
2. `TerminalParser.WriteInput` 判断是否形成完整命令。
3. `sendCommandRecord` 保存上一条命令记录。
4. `IsMatchCommandRule` 匹配命令过滤 ACL。
5. 命中 `ActionReview` 后进入 `StatusQuery`。
6. 用户确认继续后进入 `StatusStart`。
7. `waitCommandConfirm` 调用：

```text
POST /api/v1/acls/command-filter-acls/command-review/
```

8. JumpServer 返回工单状态查询接口和关闭接口。
9. KoKo 每 10 秒轮询工单状态。
10. 状态为 `approved` 时放行命令。
11. 状态为 `rejected` 或 `closed` 时禁止命令。

## 新增接口逻辑要求

KoKo 侧不新增拍照接口。KoKo 继续只调用 JumpServer 的命令复核接口，但需要兼容 JumpServer 增加的人脸核验前置逻辑。

### 1. 提交命令复核

调用接口保持：

```text
POST /api/v1/acls/command-filter-acls/command-review/
```

请求体保持：

```json
{
  "session_id": "当前会话 ID",
  "cmd_filter_acl_id": "命令过滤 ACL ID",
  "run_command": "待执行命令"
}
```

JumpServer 新逻辑：

- 先触发拍照和人脸比对。
- 人脸通过后才创建人工审批工单。
- 人脸失败时直接返回错误，不创建工单。

KoKo 处理要求：

- 如果接口返回正常工单信息，沿用现有 `check_ticket_api` 轮询逻辑。
- 如果接口返回人脸失败、拍照失败、超时等错误，当前命令必须禁止执行。
- 禁止执行时设置命令风险等级为复核拒绝或取消，优先使用现有 `ReviewReject`。
- 终端输出应给出明确原因，例如“人脸核验失败，命令已禁止执行”。

### 2. 工单状态轮询

现有逻辑保持：

```text
GET check_ticket_api
```

状态处理保持：

```text
pending -> 继续等待
approved -> 放行命令
rejected -> 禁止命令
closed -> 禁止命令
```

注意：

- 人脸核验已在创建工单前完成，KoKo 不需要单独轮询人脸状态。
- 如果 JumpServer 选择让 `command-review` 长连接等待人脸回调，KoKo 会阻塞在 `SubmitCommandReview`，需要配置合理 HTTP 超时。
- 更推荐 JumpServer 在服务端等待拍照回调并返回最终是否创建工单，KoKo 仍保持简单状态机。

### 3. 取消逻辑

现有取消逻辑保持：

- 用户按 `CTRL+C` 取消等待时调用 `CancelConfirmByRequestInfo`。
- 会话关闭时调用 `CancelConfirmByRequestInfo`。

新增要求：

- 如果人工工单尚未创建，而 JumpServer 仍处于拍照/比对阶段，JumpServer 应负责取消或标记人脸核验任务。
- KoKo 无需知道拍照任务内部状态。

### 4. 命令记录

KoKo 现有命令记录字段：

```text
session
org_id
input
output
user
asset
account
timestamp
risk_level
cmd_filter_acl
cmd_group
```

建议最小改动：

- 继续上报现有字段。
- 人脸记录由 JumpServer 用 `session_id + run_command + ticket_id + 时间窗口` 关联。

如果需要更强关联，可扩展：

```text
face_verify_id
face_verify_sign
```

但这会影响 KoKo model、命令存储和 JumpServer serializer，除非审计关联不准确，否则不建议第一阶段增加。

## 终端提示建议

需要新增或调整提示语：

```text
Need face verification before command review.
Waiting for camera photo and face comparison.
Face verification failed, command is forbidden.
Face verification timeout, command is forbidden.
Face verification passed, waiting for reviewers.
```

对应中文：

```text
命令复核前需要进行人脸核验。
正在等待摄像头抓拍和人脸比对。
人脸核验失败，命令已禁止执行。
人脸核验超时，命令已禁止执行。
人脸核验通过，正在等待审批人复核。
```

## 验收标准

- 命中 `review` 规则的命令不会立即发往目标资产。
- JumpServer 返回人脸失败时，KoKo 不放行原始回车包。
- JumpServer 返回工单信息后，KoKo 按现有逻辑等待审批。
- 审批通过时，KoKo 放行命令。
- 审批拒绝或关闭时，KoKo 禁止命令。
- 命令记录风险等级能反映通过、拒绝、取消等结果。
