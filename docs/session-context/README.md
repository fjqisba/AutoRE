# DSH 会话上下文读取指南

本文说明如何从 DeepSeek Harness（DSH）保存的会话文件中还原完整对话上下文，使另一个 AI、脚本或工具能够"接上"同一个会话。

配套实现：`session_context.py`（同目录），依赖 `zstandard`。

---

## 1. 会话文件在哪里

```
%USERPROFILE%\.dsh\sessions\<工作区目录名>\<session-id>\session.v4.jsonl.zstd
```

- **工作区目录名**由 cwd 转义而来，例如 `D:\BIGAI\AutoRE` → `--D-BIGAI-AutoRE--`（盘符与分隔符替换为 `-`，非 ASCII 用 `~XXXX~` 形式）。
- **session-id** 形如 `session-b8103737-1590-4011-a39b-73f669c57b6a`。
- 一个会话只有这一个文件；旧版本可能是 `session.v*.jsonl`（未压缩）或 `session.jsonl`，读取时按同样逻辑处理即可。

附件（图片等）不在会话文件里，而是内容寻址存储：

```
%USERPROFILE%\.dsh\attachments\v1\objects\<hash 前两位>\<hash>
```

---

## 2. 文件格式

`session.v4.jsonl.zstd` = **zstd 压缩** + **JSON Lines**（每行一个 JSON 对象）。

首行是会话头：

```json
{"type":"session","version":4,"id":"session-...","createdAt":1792423757330,
 "cwd":"D:\\BIGAI\\AutoRE","parentSession":"session-...","isSeeded":true,
 "delegationDepth":0,"agentPreset":"standard"}
```

其余每行是一个事件：

```json
{"type":"user/message","seq":15,"time":1792418917538,"data":{...}}
```

- `seq`：单调递增的事件序号，**按它排序即可还原时间线**（文件本身通常已按序写入）。
- `time`：Unix 毫秒时间戳。
- `data`：事件负载，结构随 `type` 变化。

> 这是**事件日志**，不是聊天记录：同一条消息可能既有"入站事件"又有"拼接事件"，工具调用与结果分开记录，被模型上下文裁剪掉的消息也有单独事件。所以不能逐行直接当消息读，需要按第 4 节的规则重建。

---

## 3. 事件类型参考

| type | 作用 | 关键字段 |
|---|---|---|
| `session` | 会话头（仅首行） | `id` `cwd` `createdAt` `parentSession` `isSeeded` `agentPreset` |
| `turn/start` / `turn/end` | 一轮对话的边界 | `turn`；`reason.kind` |
| `step/start` / `step/end` | 一轮中的一个模型步骤 | `turn` `step` |
| `user/message` | 用户消息 | `data.content[]`、`data.source.kind`、`data.id` |
| `system/message` | 系统提示词（每个 turn 重复写入） | `data.message.content[]` |
| `developer/message` | 运行时注入，如工具增删 | `data.message.content[]`（`tool-addition` / `tool-removal`） |
| `assistant/message` | 模型输出 | `data.message.content[]`（`reasoning` / `text` / `tool-call`），`turn` `step` |
| `tool/call` | 工具调用（与 assistant 里的 `tool-call` 块重复，便于索引） | `callId` `name` `arguments` |
| `tool/result` | 工具结果 | `data.message.role="tool"`、`toolCallId`、`content[]`、`isError` |
| `agent/inbox/spliced` | 运行中插入的消息（审批通知、子代理回报等） | `inserted[]`，元素与消息同构 |
| `compaction/prune` | 上下文压缩，部分消息被移出模型上下文 | `shadowedSeqs[]` `shadowedRange` `shadowedTokenCount` |
| `session/title` | 会话标题 | `title` `source.kind` |
| `request/header` | 本次请求的模型配置与工具清单 | `header.config`（provider/model/maxTokens）、`header.tools[]` |
| `request/context` | 上下文窗口信息 | `provider` `model` `contextWindow` |
| `job/registered` / `job/settled` | 后台任务生命周期 | `jobId` `kind` `status` |
| `session-log-deepseek/delivery-accepted` | 消息投递确认（内部） | 可忽略 |
| `workspace/changes` | 工作区文件变更记录 | 可忽略 |
| `web/deepseek-search-llm-request` | 搜索请求记录 | 可忽略 |

`source.kind` 的常见值：`user`、`user-approval`（审批状态变化提示）、`tool`、`tool-registry`、`system-reminder`。

---

## 4. 还原上下文的算法

```
events = zstd_decode(file) 按行解析
header = 第一个 type == "session" 的事件

pruned = ∪ compaction/prune.shadowedSeqs
messages = []
seen = set()

for e in events (按 seq):
    if e.type in ("user/message", "system/message", "developer/message"):
        msg = e.data.message ?? e.data       # 两种存储形态都要兼容
        if msg.id in seen: continue          # 入站事件与 spliced 会重复
        seen.add(msg.id); messages.append(msg)

    elif e.type == "agent/inbox/spliced":
        for m in e.data.inserted: 同上（去重后按顺序插入）

    elif e.type == "assistant/message":
        msg = e.data.message; 记录 turn/step
        可选：过滤 content 中 type == "reasoning" 的块

    elif e.type == "tool/result":
        msg = e.data.message   # role=tool, toolCallId 指向对应的 tool-call

    elif e.type == "session/title":
        title = e.data.title

# 默认排除 pruned 中的消息；需要完整历史时再打开
context = [m for m in messages if m.seq not in pruned]
```

要点：

1. **去重**：`agent/inbox/spliced` 插入的消息随后还会以 `user/message` 出现，必须按 `message.id` 去重，否则上下文里会出现两遍。
2. **消息两种形态**：`user/message` 的负载直接在 `data` 上；`system/developer/assistant/tool` 的在 `data.message` 里。
3. **工具调用**：`tool-call` 块位于 assistant 消息的 `content[]` 中，`id` 对应 `tool/result.toolCallId`；顶层的 `tool/call` 事件是同一条调用的索引副本，不要重复计入。
4. **系统提示词**：`system/message` 每轮都会写入一份，消费方**只取最后一条**作为当前系统提示。
5. **裁剪**：`compaction/prune.shadowedSeqs` 里的消息已不在模型上下文中，但对"完整历史"仍有价值，按需保留。
6. **分支/续接**：`parentSession` 非空表示该会话从别的会话续接而来；`isSeeded=true` 时开头几条可能是审批/运行时提示，不一定是用户的第一句话。

---

## 5. 便携上下文格式

`session_context.py --out context.json` 输出：

```json
{
  "session": {
    "id": "session-...", "cwd": "D:\\BIGAI\\AutoRE", "createdAt": 1792423757330,
    "parentSession": "session-...", "title": "三角战略分析 (1)",
    "model": "deepseek-flash"
  },
  "prunedSeqs": [121, 122],
  "tools": ["read", "write", "pwsh", "..."],
  "messageCount": 1285,
  "messages": [
    {"role": "user", "content": [{"type": "text", "text": "..."}], "seq": 15},
    {"role": "assistant", "turn": 1, "step": 1, "seq": 28,
     "content": [{"type": "text", "text": "..."},
                 {"type": "tool-call", "id": "call_00_...", "name": "web_search",
                  "arguments": "{\"queries\":[...]}"}]},
    {"role": "tool", "tool_call_id": "call_00_...", "content": [{"type": "text", "text": "..."}], "seq": 39}
  ]
}
```

`content` 块类型：

| 块类型 | 字段 |
|---|---|
| `text` | `text` |
| `reasoning` | `text`（思维链，默认被过滤） |
| `tool-call` | `id` `name` `arguments`（JSON 字符串） |
| `image` | `attachment.attachmentId`（`sha256:...`）、`mediaType` `width` `height` `name` |

---

## 6. 使用

```powershell
pip install zstandard

# 用 session id 或文件路径
python session_context.py session-b8103737-1590-4011-a39b-73f669c57b6a `
    --out context.json --md transcript.md

# 可选参数
#   --include-reasoning   保留思维链
#   --include-pruned      保留已被上下文裁剪的消息
#   --last 40             只取最近 40 条（控制 token）
```

脚本会扫描 `~/.dsh/sessions` 自动定位会话；同一 id 命中多份时取最近修改的。

---

## 7. 其他 AI 如何消费

1. **系统提示**：取 `messages` 中最后一条 `role=system` 作为 system prompt。
2. **工具结果**：按 `tool_call_id` 与 assistant 的 `tool-call` 配对；不支持 function calling 的模型可把 `tool-call` 扁平化成文本（`调用 web_search：{...}`），把结果作为普通文本。
3. **思维链**：`reasoning` 块可丢弃（多数模型不需要），需要时再开 `--include-reasoning`。
4. **图片**：`attachmentId` 形如 `sha256:abc...`，文件在 `attachments/v1/objects/ab/abc...`；没有该文件时按 `name` 说明降级为文本占位。
5. **token 预算**：上下文可能很大（示例会话 1.08M 字符 ≈ 30 万 token），建议按 `--last` 截断或先做摘要，而不是整包塞进 prompt。
6. **裁剪消息**：`prunedSeqs` 中的内容已不在原模型上下文中；如果目标是"复现原模型看到的上下文"，应排除它们。

---

## 8. 注意事项

- **会话可能正在写入**：读取活动会话前先复制一份文件再解压，避免读到半帧；zstd 多帧流通常仍可解出已写入部分。
- **版本字段**：首行 `version` 与文件名 `v4` 对应；字段可能随版本演进，解析时对缺失字段做容错。
- **隐私**：会话包含完整提示词、命令输出、文件路径，可能含密钥或个人信息；共享前先脱敏（密钥、路径、用户名）。
- **附件是内容寻址**：同一图片只存一份，按 sha256 去重；删除会话不会自动清理附件。
- **不要把它当数据库**：事件日志包含大量内部事件（`step/*`、`job/*`、`session-log-*`），只应消费第 3 节表中列出的消息类事件。

---

## 附：本次验证

对 `session-b8103737-1590-4011-a39b-73f669c57b6a`（工作区 `D:\BIGAI\AutoRE`）实测：

| 指标 | 值 |
|---|---|
| 会话文件 | 2.2 MB（zstd） |
| 事件数 | 4,681 |
| 还原消息数 | 1,297（assistant 601 / tool 585 / user 102 / system 9） |
| 被裁剪消息 | 11 |
| 工具数 | 41 |
| 上下文体积 | 约 1.1M 字符（≈ 30 万 token，随会话增长） |
| 标题 / 模型 | 三角战略分析 (1) / deepseek-flash |

