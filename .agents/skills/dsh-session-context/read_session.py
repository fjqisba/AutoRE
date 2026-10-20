"""还原 DSH 会话上下文：python read_session.py <id|file> [--last N] [--all] [--reasoning]"""
import argparse, json, os, sys

try:
    import zstandard
except ImportError:
    sys.exit("pip install zstandard")


def find(arg):
    if os.path.isfile(arg):
        return arg
    for dp, _, fs in os.walk(os.path.expanduser("~/.dsh/sessions")):
        if arg in dp and "session.v4.jsonl.zstd" in fs:
            return os.path.join(dp, "session.v4.jsonl.zstd")
    sys.exit("session not found: " + arg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session")
    ap.add_argument("--last", type=int)
    ap.add_argument("--all", action="store_true", help="保留被裁剪的消息")
    ap.add_argument("--reasoning", action="store_true")
    a = ap.parse_args()

    path = find(a.session)
    with open(path, "rb") as f:
        raw = zstandard.ZstdDecompressor().stream_reader(f).read()
    events = [json.loads(x) for x in raw.decode().splitlines() if x.strip()]

    pruned = {s for e in events if e["type"] == "compaction/prune"
              for s in e["data"].get("shadowedSeqs", [])}
    msgs, seen = [], set()

    def add(m, seq):
        if m.get("id") and m["id"] in seen:   # spliced 与 user/message 会重复
            return
        if m.get("id"):
            seen.add(m["id"])
        if a.all or seq not in pruned:
            msgs.append({"role": m.get("role", "user"), "content": m.get("content"),
                         "tool_call_id": m.get("toolCallId"), "seq": seq})

    for e in events:
        if "data" not in e:   # 首行是会话头，没有 data
            continue
        t, d, seq = e["type"], e["data"], e["seq"]
        if t in ("user/message", "system/message", "developer/message", "tool/result"):
            add(d.get("message") or d, seq)
        elif t == "assistant/message":
            m = dict(d.get("message") or {})
            if not a.reasoning:   # 思维链默认丢弃
                m["content"] = [b for b in m.get("content", []) if b.get("type") != "reasoning"]
            add(m, seq)
        elif t == "agent/inbox/spliced":
            for m in d.get("inserted", []):
                add(m, seq)

    if a.last:
        msgs = msgs[-a.last:]
    json.dump(msgs, sys.stdout, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()


