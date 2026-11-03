"""从已发布状态及 SVG 文本生成前沿报告；只读取矢量文件，不生成位图。"""
from pathlib import Path
import argparse
import json
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
args = parser.parse_args()
directory = args.directory
state = json.loads((directory / "state-machine.json").read_text(encoding="utf-8"))
graph = json.loads((directory / "semantic-graph.json").read_text(encoding="utf-8"))
history = json.loads((directory / "initialization.progress.json").read_text(encoding="utf-8"))
svg_text = (directory / "semantic-graph.svg").read_text(encoding="utf-8")
dot_text = (directory / "semantic-graph.dot").read_text(encoding="utf-8")
svg = ET.fromstring(svg_text)
svg_visible = "\n".join(svg.itertext())
visible_labels = {" ".join(text.split()) for text in svg.itertext()}
assert "<image" not in svg_text
assert "BYTES" not in svg_visible and "BYTES" not in dot_text
rows = [row for node in graph["nodes"].values() for row in node.get("instructions", [])]
for row in rows:
    label = f'({row["rip"]}, {row["vip"]})  {row["assembly"]}'
    assert " ".join(label.split()) in visible_labels, label
assert len(rows) == sum(len(block["instructions"]) for block in state["blocks"])
ret_path = directory / "function-analysis.json"
terminal = json.loads(ret_path.read_text(encoding="utf-8")) if ret_path.exists() else None
error_path = directory / "initialization.error.json"
error = json.loads(error_path.read_text(encoding="utf-8")) if error_path.exists() else None
if error and len(error.get("history", [])) < len(history):
    error = None  # 历史失败文件不能覆盖较新的、已发布的状态。
last = state["blocks"][-1]["instructions"][-1]
summary = {
    "entry": f'0x{state["entry"]:X}', "blocks": len(state["blocks"]),
    "instruction_rows_verified": len(rows), "edges": len(graph["edges"]),
    "last_instruction": f'0x{last["pc"]:X}', "assembly": last["text"],
    "vip": f'0x{history[-1]["output_vip"] or 0:X}',
    "branch": history[-1]["branch"], "returned": bool(terminal and terminal["status"] == "returned"),
    "terminal": terminal, "error": None if not error else {key: error[key] for key in ("code", "block", "message")},
    "svg_parsed": True, "every_instruction_label_verified": True, "raster_used": False,
    "frontier_18131e62f": {
        "vip": "0x18022EA1A", "target": "0x1810E56EE", "kind": "direct",
        "formula": "0x1DC422334 + sign_extend_64(0xA4CC33BA)",
        "original_stop_reason": "INITIALIZATION_BUDGET_EXCEEDED after 32 native blocks",
    },
}
(directory / "analysis.verification.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
outcome = (f'已在 `{terminal["native_ret"]}` 证明返回调用者。' if summary["returned"]
           else f'尚未证明返回调用者。当前前沿为 `{summary["last_instruction"]}`，'
                f'VIP=`{summary["vip"]}`。')
reason = ("无失败诊断。" if not error else
          f'`{error["code"]}`：{error["message"]}')
report = f'''# VM 函数路径分析

{outcome}

入口为 `{summary["entry"]}`。已发布 {summary["blocks"]} 个原生基本块、
{summary["instruction_rows_verified"]} 条逐指令语义行和 {summary["edges"]} 条边。
当前分支分类为 `{summary["branch"]["kind"]}`。{reason}

## 原停止位置

`(0x18131E62F, 0x18022EA1A) jmp rcx` 的目标是唯一常量 `0x1810E56EE`：

```text
RCX = 0x1DC422334 + sign_extend_64(0xA4CC33BA)
    = 0x1DC422334 - 0x5B33CC46
    = 0x1810E56EE
```

中间 PUSHFQ/POPFQ 保存恢复 flags；前块 PUSH RCX 与后继首条 POP RCX 对应。
旧停止来自固定 32 块预算，并非 RCX 计算失败或发现双目标 JCC。

## 继续分析的依据

沿唯一目标继续，共享 State 和 memory token；后续栈 MBA 只有经位向量反例查询
UNSAT 证明等价后才规范化，不关闭未知别名或写入屏障。函数模式使用稳定 prefix
追加后继，保留全部原生块、逐指令 RIP/VIP 与快照条件。

调用者返回要求实际 RET、入口栈恢复、返回地址来自入口返回槽，并证明该槽未被
覆盖或未知别名写破坏；内部 CALL/RET 仍是状态机转移。详细结果在
[验证记录](analysis.verification.json)，语义结果在 [状态机](state-machine.json)。

## 阅读产物

- [逐指令 SVG 流程图](semantic-graph.svg)
- [Graphviz DOT 源码](semantic-graph.dot)
- [优化后的 LLVM IR](block.optimized.ll)
- [路径证据](initialization.progress.json)

SVG 已按 XML 解析，并逐条核对 `(RIP, VIP) 汇编指令` 标签与路径的指令总数。
未生成或读取 PNG，图中没有 BYTES 列。

所有确定目标仍依赖只读 PE 快照、首选基址及已声明的正常完成观察契约。
不将本条路径验证扩展为目标 DLL 全输入、异常或并发行为的等价证明。
'''
(directory / "ANALYSIS.md").write_text(report, encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
