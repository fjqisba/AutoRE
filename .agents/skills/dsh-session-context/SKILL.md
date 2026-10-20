---
name: dsh-session-context
description: 读取 DeepSeek Harness 会话文件（~/.dsh/sessions/**/session.v4.jsonl.zstd）并还原完整对话上下文，供其他 AI、脚本或工具接续同一会话；包含事件日志到消息列表的还原规则、去重、上下文裁剪与附件回查。
metadata:
  short-description: 还原 DSH 会话上下文
---

# DSH 会话上下文

## 位置

```
~/.dsh/sessions/<工作区转义>/<session-id>/session.v4.jsonl.zstd   # zstd + JSONL
~/.dsh/attachments/v1/objects/<hash 前 2 位>/<hash>              # 附件
```

首行 `type=session`：`id` `cwd` `parentSession` `isSeeded`；其余每行 `{type,seq,time,data}`。

## 事件

| type | 用途 |
|---|---|
| `user/system/developer/message` | 消息（负载在 `data` 或 `data.message`） |
| `assistant/message` | 输出，`content[]`：`reasoning`/`text`/`tool-call` |
| `tool/result` | 结果，`role=tool`、`toolCallId` |
| `agent/inbox/spliced` | 运行中插入的消息 `inserted[]` |
| `compaction/prune` | `shadowedSeqs` 为已移出上下文的消息 |
| `request/header` | 模型配置与工具清单 |

`step/*`、`job/*`、`session-log-*`、`request/*` 忽略。

## 还原规则

1. 按 `seq` 排序；消息体取 `data.message ?? data`。
2. 按 `message.id` 去重：`spliced` 插入的消息随后会再以 `user/message` 出现。
3. `tool-call` 块已在 assistant 的 `content[]` 内，顶层 `tool/call` 是索引副本，不重复计。
4. `system/message` 每轮重写，只取最后一条作系统提示。
5. 默认排除 `shadowedSeqs`；需要完整历史时保留。

## 用法

```powershell
pip install zstandard
python read_session.py <session-id|文件路径> [--last N] [--all] [--reasoning]
```

## 坑

- 活动会话先复制再解压，避免读到半帧。
- 附件按 `attachmentId`（`sha256:...`）回查，缺失时降级为文本占位。
- 体积可达百万字符，按 `--last` 截断或先摘要。
- 含提示词、命令输出与路径，共享前脱敏。
