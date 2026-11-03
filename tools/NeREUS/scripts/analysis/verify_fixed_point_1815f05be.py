"""用已保存的合并链回归不动点优化，不执行 DLL，也不扩展后继。"""
from pathlib import Path
import json
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "temp_data/vjmp/180914deb/rounds/10"
OUT = ROOT / "temp_data/analysis/jmp-1815f05be/fixed-point"
OUT.mkdir(parents=True, exist_ok=True)
facts = json.loads((SOURCE / "image-facts.json").read_text(encoding="utf-8"))["facts"]


def optimize(name, budget=None):
    directory = OUT / name
    directory.mkdir(parents=True, exist_ok=True)
    request = {
        "protocol_version": 1, "request_id": 1, "op": "optimize-local",
        "input_bitcode": str(SOURCE / "block.lifted.bc"),
        "output_dir": str(directory), "function_name": "nereus_bb_180914deb",
        "image_facts": facts,
    }
    if budget is not None:
        request["iteration_budget"] = budget
    result = subprocess.run(
        [str(ROOT / "toolchains/bin/nereus-remill-worker.exe")],
        input=json.dumps(request) + "\n", text=True, capture_output=True,
        check=True, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    response = json.loads(result.stdout)
    assert response["ok"], response
    (directory / "optimization.json").write_text(
        json.dumps(response, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return response


limited = optimize("budget-8", 8)
assert not limited["converged"]
assert limited["iteration_budget_exhausted"]
assert limited["stop_reason"] == "iteration-budget-exhausted"
stable = optimize("default")
assert stable["converged"]
assert stable["stop_reason"] == "fixed-point"
assert stable["initialization"]["next_target"] == "0x181562c26"
assert stable["branch_analysis"]["kind"] == "direct"
assert not stable["iteration_history"][-1]["ir_changed"]
assert not stable["iteration_history"][-1]["state_changed"]
# 恰好最后一轮达到稳定时，不能误报预算耗尽。
exact = optimize("exact-budget", stable["iterations"])
assert exact["converged"] and not exact["iteration_budget_exhausted"]
summary = {
    "rip": "0x1815F05BE", "vip": "0x18022E986", "target": "0x181562C26",
    "kind": stable["branch_analysis"]["kind"], "converged": stable["converged"],
    "iterations": stable["iterations"], "snapshot_facts": len(facts),
    "snapshot_reads_promoted": stable["snapshot_reads_promoted"],
    "instructions_before": stable["instructions_before"],
    "instructions_before_outlining": stable["instructions_before_outlining"],
    "instructions_after": stable["instructions_after"],
    "instructions_including_helpers": stable["total_instructions_including_helpers"],
    "saved_gpr_count": stable["initialization"]["saved_gpr_count"],
    "runtime_context_writes": len(stable["initialization"]["runtime_context_writes"]),
    "context_complete": stable["initialization"]["complete"],
    "observation_model": stable["observation_model"],
    "budget_8_converged": limited["converged"],
    "exact_budget_converged": exact["converged"],
    "llvm_only_changes": [row["iteration"] for row in stable["iteration_history"]
                          if row["ir_changed"] and not any(row[key] for key in (
                              "state_reads_forwarded", "guest_reads_forwarded",
                              "snapshot_reads_promoted", "overwritten_guest_writes_removed"))],
    "successors_expanded": False, "original_dll_executed": False,
}
(OUT / "verification.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
print(json.dumps(summary, ensure_ascii=False, indent=2))
