"""复现单个 vjmp 的公式、快照输入及有限位向量恒等式；不展开后继。"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'temp_data/analysis/jmp-1815f05be'
MODULE=ROOT.parents[1]/'temp_data/ACE_WINDOWS/ACE-DFS64.dll'
OUT.mkdir(parents=True,exist_ok=True)
image=MODULE.read_bytes()
nt=struct.unpack_from('<I',image,0x3c)[0]
optional=nt+24
base=struct.unpack_from('<Q',image,optional+24)[0]
section_table=optional+struct.unpack_from('<H',image,nt+20)[0]
section_count=struct.unpack_from('<H',image,nt+6)[0]

def read32(address):
    rva=address-base
    for index in range(section_count):
        start=section_table+index*40
        _,va,raw_size,raw_pointer=struct.unpack_from('<IIII',image,start+8)
        if va<=rva and rva+4<=va+raw_size:
            offset=raw_pointer+rva-va
            value=struct.unpack_from('<I',image,offset)[0]
            return {'address':f'0x{address:X}','file_offset':f'0x{offset:X}',
                    'bytes':image[offset:offset+4].hex(),'value':f'0x{value:08X}'}
    raise ValueError(f'没有映射：{address:#x}')

vip=0x18022E986
pointer=read32(vip-8)
left=read32(vip-4)
right=read32(base+int(pointer['value'],16))
constants=[read32(address)for address in [0x18105E608,0x18177BBA2,0x18105E5C3,0x18177BBA6]]
k1=int(constants[0]['value'],16)^int(constants[1]['value'],16)
k2=int(constants[2]['value'],16)^int(constants[3]['value'],16)
sum32=(int(left['value'],16)+int(right['value'],16))&0xFFFFFFFF
delta32=sum32^k1
signed=delta32-(1<<32)if delta32&(1<<31)else delta32
target=(0x181562C26+signed)&((1<<64)-1)

# 验证汇编的三段混淆分别等价于 read32 相加、xor 常量和 base+有符号偏移。
proof=r'''
(set-logic QF_BV)
(declare-const a (_ BitVec 32))
(declare-const b (_ BitVec 32))
(declare-const k (_ BitVec 32))
(define-fun r9temp () (_ BitVec 32) (bvor (bvand (bvadd a b) a) a))
(define-fun total () (_ BitVec 32) (bvadd b r9temp))
(define-fun encoded32 () (_ BitVec 32) (bvor (bvxor total k) (bvand (bvxor total k) total)))
(declare-const h (_ BitVec 64))
(declare-const d (_ BitVec 64))
(define-fun c0 () (_ BitVec 64) (bvnot h))
(define-fun c1 () (_ BitVec 64) (bvnot (bvor c0 (bvnot d))))
(define-fun c2 () (_ BitVec 64) (bvnot (bvor c1 h)))
(define-fun finalbase () (_ BitVec 64) (bvnot (bvor (bvnot h) c2)))
(push)
(assert (distinct encoded32 (bvxor (bvadd a b) k)))
(check-sat)
(pop)
(push)
(assert (distinct (bvadd d finalbase) (bvadd d h)))
(check-sat)
(pop)
'''
config=json.loads((ROOT/'toolchains/local.json').read_text(encoding='utf-8-sig'))
flags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess,'CREATE_NO_WINDOW')else 0
solver=subprocess.run([config['z3'],'-in','-T:2'],input=proof,text=True,capture_output=True,check=True,creationflags=flags)
assert solver.stdout.split()==['unsat','unsat'],solver.stdout
(OUT/'formula-proof.smt2').write_text(proof,encoding='utf-8')
(OUT/'formula-proof.result.txt').write_text(solver.stdout,encoding='utf-8')
result={'module_sha256':hashlib.sha256(image).hexdigest(),'rip':'0x1815F05BE','vip':f'0x{vip:X}',
    'handler_base':'0x181562C26','pointer_operand':pointer,'left_operand':left,'right_operand':right,
    'constant_operands':constants,'xor_constant_1':f'0x{k1:08X}','xor_constant_2':f'0x{k2:08X}',
    'sum32':f'0x{sum32:08X}','delta32':f'0x{delta32:08X}','target':f'0x{target:X}',
    'identity_queries':solver.stdout.split(),
    'scope':'supplied-readonly-PE-snapshot; expression only; no successor expansion'}
(OUT/'formula.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
