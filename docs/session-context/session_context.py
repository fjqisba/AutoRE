"""读取 DeepSeek Harness (DSH) 会话文件，还原成可共享的对话上下文。

用法:
    python session_context.py <session-id | session.v4.jsonl.zstd> \
        [--out context.json] [--md transcript.md] \
        [--include-reasoning] [--include-pruned] [--last N]

会话文件默认位于 %USERPROFILE%\\.dsh\\sessions\\<工作区>\\<session-id>\\session.v4.jsonl.zstd
内容为 zstd 压缩的 JSONL：首行是会话头，其余每行一个事件 {type, seq, time, data}。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

try:
    import zstandard
except ImportError:  # pragma: no cover
    sys.exit("需要 zstandard：pip install zstandard")


def resolve(path_or_id: str) -> str:
    if os.path.isfile(path_or_id):
        return path_or_id
    home = os.path.expanduser("~")
    root = os.path.join(home, ".dsh", "sessions")
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if fn == "session.v4.jsonl.zstd" and path_or_id in dirpath:
                hits.append(os.path.join(dirpath, fn))
    if not hits:
        sys.exit(f"找不到会话：{path_or_id}")
    if len(hits) > 1:
        # 取最近修改的一个
        hits.sort(key=os.path.getmtime, reverse=True)
    return hits[0]


def load_events(path: str):
    with open(path, "rb") as f:
        raw = zstandard.ZstdDecompressor().stream_reader(f).read()
    return [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]


def blocks_text(content) -> str:
    out = []
    for b in content or []:
        t = b.get("type")
        if t == "text":
            out.append(b.get("text", ""))
        elif t == "image":
            out.append(f"[image: {b.get('name') or b.get('path') or b.get('mediaType', 'image')}]")
        elif t == "tool-call":
            out.append(f"[tool-call {b.get('name')}]")
    return "\n".join(x for x in out if x)


def build_context(events, include_reasoning=False, include_pruned=False, last=None):
    header = next((e for e in events if e.get("type") == "session"), {})
    pruned = set()
    for e in events:
        if e.get("type") == "compaction/prune":
            pruned.update(e.get("data", {}).get("shadowedSeqs", []) or [])

    messages = []
    seen_ids = set()
    title = None
    tools = {}

    def add(msg):
        mid = msg.get("id")
        if mid:
            if mid in seen_ids:
                return
            seen_ids.add(mid)
        if not include_pruned and msg.get("_seq") in pruned:
            return
        messages.append(msg)

    for e in events:
        typ = e.get("type")
        seq = e.get("seq")
        data = e.get("data", {}) or {}

        if typ == "session/title":
            title = data.get("title") or title

        elif typ == "request/header":
            for t in data.get("header", {}).get("tools", []) or []:
                tools[t.get("name")] = t.get("description", "")

        elif typ in ("user/message", "system/message", "developer/message"):
            # 两类存储：data 直接是消息，或 data.message 包着消息
            msg = dict(data.get("message") or data)
            msg["_seq"] = seq
            if typ == "user/message":
                add(msg)
            elif typ == "system/message":
                add(msg)  # 系统提示词按轮次重复，由消费方只取最后一条

        elif typ == "agent/inbox/spliced":
            for item in data.get("inserted", []) or []:
                m = dict(item)
                m["_seq"] = seq
                add(m)

        elif typ == "assistant/message":
            msg = dict(data.get("message") or {})
            msg["_seq"] = seq
            msg["turn"] = data.get("turn")
            msg["step"] = data.get("step")
            if not include_reasoning:
                msg["content"] = [b for b in msg.get("content", []) if b.get("type") != "reasoning"]
            add(msg)

        elif typ == "tool/result":
            msg = dict(data.get("message") or {})
            msg["_seq"] = seq
            add(msg)

    # 只保留实际发给模型的消息（工具调用在 assistant 的 tool-call 块里，结果单独成条）
    cleaned = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content")
        rec = {"role": role, "content": content}
        if m.get("toolCallId"):
            rec["tool_call_id"] = m["toolCallId"]
        if m.get("isError"):
            rec["is_error"] = True
        if m.get("source"):
            rec["source"] = m["source"]
        if m.get("turn") is not None:
            rec["turn"] = m["turn"]
            rec["step"] = m.get("step")
        rec["seq"] = m.get("_seq")
        cleaned.append(rec)

    if last:
        cleaned = cleaned[-last:]

    return {
        "session": {
            "id": header.get("id"),
            "cwd": header.get("cwd"),
            "createdAt": header.get("createdAt"),
            "parentSession": header.get("parentSession"),
            "title": title,
            "model": next((e["data"].get("model") for e in events if e.get("type") == "request/context"), None),
        },
        "prunedSeqs": sorted(pruned),
        "tools": sorted(tools),
        "messageCount": len(cleaned),
        "messages": cleaned,
    }


def to_markdown(ctx, path):
    lines = [f"# {ctx['session'].get('title') or ctx['session'].get('id')}", ""]
    for m in ctx["messages"]:
        role = m["role"]
        if role == "system":
            continue
        if role == "tool":
            body = blocks_text(m.get("content"))
            lines.append(f"> **tool** `{m.get('tool_call_id', '')}`\n>\n" +
                         "\n".join("> " + x for x in body.splitlines()[:40]))
            lines.append("")
            continue
        body = blocks_text(m.get("content"))
        if m.get("source", {}).get("kind") == "tool-call":
            continue
        lines.append(f"## {role}")
        lines.append("")
        lines.append(body)
        lines.append("")
    open(path, "w", encoding="utf-8").write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session")
    ap.add_argument("--out", default="context.json")
    ap.add_argument("--md", default=None)
    ap.add_argument("--include-reasoning", action="store_true")
    ap.add_argument("--include-pruned", action="store_true")
    ap.add_argument("--last", type=int, default=None)
    args = ap.parse_args()

    path = resolve(args.session)
    events = load_events(path)
    ctx = build_context(events, args.include_reasoning, args.include_pruned, args.last)
    ctx["sourceFile"] = path

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(ctx, f, ensure_ascii=False, indent=1)
    if args.md:
        to_markdown(ctx, args.md)

    print(f"events={len(events)} messages={ctx['messageCount']} "
          f"pruned={len(ctx['prunedSeqs'])} -> {args.out}")


if __name__ == "__main__":
    main()
