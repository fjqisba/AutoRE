"""只读查询已打开的 IDA Nexus 数据库，不保存或修改用户数据库。"""
from pathlib import Path
import json
from ida_nexus import DatabaseHandle, discover_databases

OUTPUT = Path(__file__).resolve().parents[2] / "temp_data" / "ida-context"
OUTPUT.mkdir(parents=True, exist_ok=True)
owners = [entry.instance for entry in discover_databases()
          if Path(entry.instance.idb_path).name.lower() == "ace-dfs64.dll.i64"]
if len(owners) != 1:
    raise RuntimeError("未找到用户指定模块的唯一已打开 Nexus 实例")
owner = owners[0]
# 注册信息包含认证信息，仅输出非敏感的连接与数据库标识。
print(json.dumps({"backend": owner.backend, "idb_path": owner.idb_path, "requested_port": 2216, "registered_port": owner.port}))
code = r'''
import idaapi, ida_nalt, ida_segment, ida_funcs, ida_bytes, idautils, idc, json
targets = [0x180914DEB, 0x181058BEA, 0x1814A5C34]
items = []
for target in targets:
    instructions=[]
    ea=target
    for index in range(100):
        size=ida_bytes.get_item_size(ea)
        mnemonic=idc.print_insn_mnem(ea)
        instructions.append({"ea":hex(ea),"bytes":ida_bytes.get_bytes(ea,size).hex() if size else None,"asm":idc.generate_disasm_line(ea,0)})
        if mnemonic.startswith('j') or mnemonic in ('call','retn','ret','int','int3'): break
        ea+=max(size,1)
    refs=list(idautils.XrefsTo(target,0))
    callers=[]
    for ref in refs[:12]:
        lo=ref.frm
        for index in range(5): lo=idc.prev_head(lo)
        context=[]; cursor=lo
        while cursor<=ref.frm:
            context.append({"ea":hex(cursor),"asm":idc.generate_disasm_line(cursor,0)})
            cursor=idc.next_head(cursor)
        callers.append({"source":hex(ref.frm),"type":int(ref.type),"context":context})
    seg=ida_segment.getseg(target)
    items.append({"target":hex(target),"section":ida_segment.get_segm_name(seg) if seg else None,"instructions":instructions,"xref_count":len(refs),"xref_examples":callers})
result={"image_base":hex(ida_nalt.get_imagebase()),"root_file":ida_nalt.get_root_filename(),"targets":items}
'''
with DatabaseHandle.open(owner.idb_path) as handle:
    execution = handle.execute_python(code, timeout=30, operation_label="NeREUS: context state and internal-call xrefs", flush_database=False)
result = execution["result"]
(OUTPUT / "ida-context-xrefs.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(result, ensure_ascii=False, indent=2))
