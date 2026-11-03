"""证明首次运行时分支的两个目标及其零/非零谓词，不指定实际运行时值。"""
from pathlib import Path
import json
import re
import subprocess

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/"temp_data/vm-function/ace-proof-prefix/180914deb"
OUT=ROOT/"temp_data/analysis/vm-exit/runtime-branch"
OUT.mkdir(parents=True,exist_ok=True)
state=json.loads((SOURCE/"state-machine.json").read_text(encoding="utf-8"))
model=state["prepared"]["optimization"]["branch_analysis"]
address=0x1801AA118
inputs=[row for row in model["inputs"] if "__remill_read_memory_64" in row["source"]
        and f"i64 noundef {address}" in row["source"]]
assert len(inputs)==1
symbol=inputs[0]["name"]
config=json.loads((ROOT/"toolchains/local.json").read_text(encoding="utf-8-sig"))

def solve(text):
    result=subprocess.run([config["z3"],"-in","-T:5"],input=text,text=True,capture_output=True,
                          check=True,creationflags=subprocess.CREATE_NO_WINDOW)
    return result.stdout.strip()

rows=[]
for zero in (True,False):
    name="zero" if zero else "nonzero"
    predicate=f"(= {symbol} (_ bv0 64))"
    if not zero:predicate=f"(not {predicate})"
    base=model["smt2"]+f"(assert {predicate})\n"
    query=base+"(check-sat)\n(get-value (target))\n"
    output=solve(query)
    match=re.search(r"#x([0-9a-fA-F]+)",output)
    assert output.startswith("sat") and match,output
    target=int(match.group(1),16)
    exclusion=base+f"(assert (distinct target (_ bv{target} 64)))\n(check-sat)\n"
    status=solve(exclusion)
    assert status=="unsat",status
    (OUT/f"{name}.smt2").write_text(query,encoding="utf-8")
    (OUT/f"{name}.result.txt").write_text(output+"\n",encoding="utf-8")
    (OUT/f"{name}.exclusion.smt2").write_text(exclusion,encoding="utf-8")
    (OUT/f"{name}.exclusion.result.txt").write_text(status+"\n",encoding="utf-8")
    rows.append({"condition":f"M64(0x{address:X}) {'==' if zero else '!='} 0",
                 "target":f"0x{target:X}","unique_target_proof":status})
assert len({row["target"] for row in rows})==2
result={"native_branch":"0x1810E5776","address":f"0x{address:X}","partitions":rows,
        "partition_exhaustive":True,"runtime_value_chosen":False,
        "scope":"current-path-QF_BV-with-independent-input-overapproximation"}
(OUT/"condition-proof.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
print(json.dumps(result,ensure_ascii=False,indent=2))
