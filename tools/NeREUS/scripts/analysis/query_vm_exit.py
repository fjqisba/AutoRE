"""只读核对当前 VM 前沿、跳转常量和原生出口；不修改 IDA 数据库。"""
from pathlib import Path
import json
from ida_nexus import DatabaseHandle, discover_databases

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "temp_data/analysis/vm-exit"
OUT.mkdir(parents=True, exist_ok=True)
owners = [row.instance for row in discover_databases()
          if Path(row.instance.idb_path).name.lower() == "ace-dfs64.dll.i64"]
if len(owners) != 1:
    raise RuntimeError("用户指定的已打开数据库不唯一或不可用")
code = r'''
import ida_bytes, ida_funcs, ida_nalt, ida_segment, idautils, idc
targets=[(0x18131E600,0x18131E631),(0x1810E56EE,0x1810E5900)]
items=[]
for start,end in targets:
    rows=[]; ea=start
    while ea<end and len(rows)<180:
        size=ida_bytes.get_item_size(ea)
        rows.append({"rip":hex(ea),"assembly":idc.generate_disasm_line(ea,0)})
        if ea!=start and idc.print_insn_mnem(ea) in ('jmp','ret','retn'):break
        ea+=max(size,1)
    refs=[{"source":hex(ref.frm),"type":int(ref.type)} for ref in idautils.XrefsTo(start,0)][:24]
    items.append({"entry":hex(start),"instructions":rows,"xrefs":refs})
fn=ida_funcs.get_func(0x180914DEB)
result={"module":ida_nalt.get_root_filename(),"image_base":hex(ida_nalt.get_imagebase()),
        "queries":items,"entry_function":None if not fn else {"start":hex(fn.start_ea),"end":hex(fn.end_ea)},
        "target_arithmetic":hex((0x1DC422334 + (0xA4CC33BA-(1<<32)))&((1<<64)-1))}
'''
owner = owners[0]
with DatabaseHandle.open(owner.idb_path) as handle:
    execution = handle.execute_python(code, timeout=30,
        operation_label="NeREUS: verify jmp rcx and successor", flush_database=False)
result = execution["result"]
(OUT / "ida-frontier.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(result, ensure_ascii=False, indent=2))
