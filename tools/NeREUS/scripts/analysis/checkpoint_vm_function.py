"""保存一致的已发布前沿，供长分析安全重启；不复制未提交的轮次。"""
from pathlib import Path
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("destination", type=Path)
args = parser.parse_args()
source, destination = args.source, args.destination
for attempt in range(5):
    try:
        raw = (source / "state-machine.json").read_bytes()
        state = json.loads(raw)
        history_raw = (source / "initialization.progress.json").read_bytes()
        history = json.loads(history_raw)
        count = len(state["blocks"])
        if len(history) != count:
            continue
        round_dir = Path("rounds") / f"{count-1:02}"
        facts_raw = (source / round_dir / "image-facts.json").read_bytes()
        json.loads(facts_raw)
        if (source / "state-machine.json").read_bytes() != raw:
            continue
        (destination / round_dir).mkdir(parents=True, exist_ok=True)
        (destination / "state-machine.json").write_bytes(raw)
        (destination / "initialization.progress.json").write_bytes(history_raw)
        (destination / round_dir / "image-facts.json").write_bytes(facts_raw)
        print(json.dumps({"blocks": count, "source": str(source), "checkpoint": str(destination),
                          "next": state["initialization"].get("next_target")}, ensure_ascii=False))
        break
    except (json.JSONDecodeError, FileNotFoundError):
        continue
else:
    raise RuntimeError("正在提交前沿，未取得一致检查点；没有中止原分析")
