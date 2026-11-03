// SPDX-License-Identifier: Apache-2.0
use crate::{Cancellation, ElfImage, Function, Result};
use capstone::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub flow: String,
    pub target: Option<u64>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub instructions: usize,
    pub milliseconds: u64,
    pub span: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            instructions: 4096,
            milliseconds: 750,
            span: 1024 * 1024,
        }
    }
}
impl Limits {
    pub fn bounded(self) -> Self {
        Self {
            instructions: self.instructions.clamp(1, 32768),
            milliseconds: self.milliseconds.clamp(1, 5000),
            span: self.span.clamp(4, 16 * 1024 * 1024),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Edge {
    pub from: u64,
    pub to: Option<u64>,
    pub kind: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct BasicBlock {
    pub address: u64,
    pub end: u64,
    pub instruction_count: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct Analysis {
    pub entry: u64,
    pub instructions: Vec<Instruction>,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<Edge>,
    pub functions: Vec<Function>,
    pub partial: bool,
    pub reasons: Vec<String>,
    pub elapsed_ms: f64,
    pub limits: Limits,
}
struct Page {
    base: u64,
    data: Arc<Vec<u8>>,
}
#[derive(Default)]
struct Symbols {
    cached: Option<Arc<crate::elf::SymbolIndex>>,
    busy: bool,
}
pub struct Engine {
    pub image: Arc<ElfImage>,
    pages: Mutex<VecDeque<Page>>,
    symbols: Mutex<Symbols>,
    symbol_ready: Condvar,
}
impl Engine {
    pub fn new(image: ElfImage) -> Self {
        Self::from_image(Arc::new(image))
    }
    pub fn from_image(image: Arc<ElfImage>) -> Self {
        Self {
            image,
            pages: Mutex::new(VecDeque::new()),
            symbols: Mutex::new(Symbols::default()),
            symbol_ready: Condvar::new(),
        }
    }
    /// 并发 functions 请求共享一次索引；等待线程每 25 ms 检查取消，不重复扫描符号表。
    pub fn symbols(&self, cancel: &Cancellation) -> Result<Arc<crate::elf::SymbolIndex>> {
        let mut state = self.symbols.lock().map_err(|_| "symbol cache poisoned")?;
        loop {
            cancel.check()?;
            if let Some(index) = &state.cached {
                return Ok(index.clone());
            }
            if !state.busy {
                break;
            }
            state = self
                .symbol_ready
                .wait_timeout(state, Duration::from_millis(25))
                .map_err(|_| "symbol cache poisoned")?
                .0;
        }
        state.busy = true;
        drop(state);
        let result = self.image.symbols(cancel).map(Arc::new);
        let mut state = self.symbols.lock().map_err(|_| "symbol cache poisoned")?;
        state.busy = false;
        if let Ok(index) = &result {
            state.cached = Some(index.clone());
        }
        self.symbol_ready.notify_all();
        result
    }
    fn decoder(&self) -> Result<Capstone> {
        if self.image.machine != 183 {
            return Err(format!("ELF metadata is supported; disassembly currently requires AArch64 (e_machine=183), found {}",self.image.machine));
        }
        Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .endian(if self.image.little {
                capstone::Endian::Little
            } else {
                capstone::Endian::Big
            })
            .build()
            .map_err(|e| e.to_string())
    }
    /// 最多缓存 64 个 4 KiB 文件页（256 KiB）；文件大小不会决定缓存大小。
    fn code(&self, address: u64) -> Result<[u8; 4]> {
        if address & 3 != 0 {
            return Err("AArch64 instruction address must be 4-byte aligned".into());
        }
        let seg = self
            .image
            .segment_at(address)
            .ok_or("unmapped instruction address")?;
        if !seg.executable() {
            return Err("instruction address is not in an executable PT_LOAD".into());
        }
        let delta = address - seg.address;
        if delta.checked_add(4).is_none_or(|d| d > seg.file_size) {
            return Err("instruction has no file-backed bytes (BSS or segment end)".into());
        }
        let offset = seg.offset + delta;
        let base = offset & !4095;
        let cached = {
            let mut pages = self.pages.lock().map_err(|_| "page cache poisoned")?;
            if let Some(i) = pages.iter().position(|p| p.base == base) {
                let p = pages.remove(i).unwrap();
                let data = p.data.clone();
                pages.push_back(p);
                Some(data)
            } else {
                None
            }
        };
        let data = if let Some(data) = cached {
            data
        } else {
            let data = Arc::new(
                self.image
                    .read_file(base, (self.image.length - base).min(4096) as usize)?,
            );
            let mut pages = self.pages.lock().map_err(|_| "page cache poisoned")?;
            if pages.len() >= 64 {
                pages.pop_front();
            }
            pages.push_back(Page {
                base,
                data: data.clone(),
            });
            data
        };
        let position = (offset - base) as usize;
        if let Some(bytes) = data.get(position..position + 4) {
            Ok(bytes.try_into().unwrap())
        } else {
            self.image
                .read_file(offset, 4)?
                .try_into()
                .map_err(|_| "short instruction".into())
        }
    }
    fn decode(&self, cs: &Capstone, address: u64) -> Result<Instruction> {
        let bytes = self.code(address)?;
        let insns = cs
            .disasm_count(&bytes, address, 1)
            .map_err(|e| e.to_string())?;
        let insn = insns
            .iter()
            .next()
            .ok_or_else(|| format!("invalid AArch64 instruction at 0x{address:x}"))?;
        let word = if self.image.little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        };
        let mnemonic = insn.mnemonic().unwrap_or("").to_owned();
        let (flow, target) = flow(word, address, &mnemonic);
        Ok(Instruction {
            address,
            bytes: bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
            mnemonic,
            operands: insn.op_str().unwrap_or("").to_owned(),
            flow: flow.into(),
            target,
        })
    }
    pub fn disassemble(
        &self,
        address: u64,
        count: usize,
        cancel: &Cancellation,
    ) -> Result<Vec<Instruction>> {
        let count = count.clamp(1, 4096);
        let cs = self.decoder()?;
        let mut result = vec![];
        let segment = self.image.segment_at(address).ok_or("unmapped address")?;
        for i in 0..count {
            cancel.check()?;
            let at = address
                .checked_add(i as u64 * 4)
                .ok_or("address overflow")?;
            if at >= segment.address + segment.file_size {
                break;
            }
            match self.decode(&cs, at) {
                Ok(insn) => result.push(insn),
                Err(error) => {
                    if i == 0 && (!segment.executable() || address & 3 != 0) {
                        return Err(error);
                    }
                    // 浏览允许无效字节占位，局部函数分析遇到无效指令则停止该路径。
                    let bytes = self.code(at)?;
                    result.push(Instruction {
                        address: at,
                        bytes: bytes
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(" "),
                        mnemonic: ".byte".into(),
                        operands: error,
                        flow: "invalid".into(),
                        target: None,
                    });
                }
            }
        }
        Ok(result)
    }
    /// 以请求地址为根的有界递归下降。跟踪直接控制流，不跟进被调用函数；不扫描全段找 prologue。
    pub fn analyze(&self, address: u64, limits: Limits, cancel: &Cancellation) -> Result<Analysis> {
        let limits = limits.bounded();
        let started = Instant::now();
        let cs = self.decoder()?;
        if !self.image.executable(address) || address & 3 != 0 {
            return Err("analysis entry must be aligned executable VA".into());
        }
        let mut queue = VecDeque::from([address]);
        let mut queued = BTreeSet::from([address]);
        let mut instructions = BTreeMap::new();
        let mut edges = vec![];
        let mut leaders = BTreeSet::from([address]);
        let mut functions = BTreeMap::new();
        let mut reasons = BTreeSet::new();
        while let Some(mut at) = queue.pop_front() {
            loop {
                cancel.check()?;
                if instructions.contains_key(&at) {
                    break;
                }
                if instructions.len() >= limits.instructions {
                    reasons.insert("instruction budget exhausted".into());
                    break;
                }
                if started.elapsed() >= Duration::from_millis(limits.milliseconds) {
                    reasons.insert("time budget exhausted".into());
                    break;
                }
                if at.abs_diff(address) > limits.span || !self.image.executable(at) {
                    reasons.insert(
                        "control-flow target outside requested span/executable mapping".into(),
                    );
                    break;
                }
                let insn = match self.decode(&cs, at) {
                    Ok(i) => i,
                    Err(e) => {
                        reasons.insert(e);
                        break;
                    }
                };
                let next = at.checked_add(4).ok_or("address overflow")?;
                let flow = insn.flow.clone();
                let target = insn.target;
                instructions.insert(at, insn);
                if flow == "call" {
                    edges.push(Edge {
                        from: at,
                        to: target,
                        kind: "call".into(),
                    });
                    if let Some(target) = target.filter(|a| self.image.executable(*a)) {
                        functions.entry(target).or_insert(Function {
                            address: target,
                            size: 0,
                            name: format!("sub_{target:X}"),
                            source: "direct BL target (candidate)".into(),
                        });
                    }
                }
                if flow == "branch" || flow == "conditional" {
                    edges.push(Edge {
                        from: at,
                        to: target,
                        kind: if flow == "conditional" {
                            "taken"
                        } else {
                            "branch"
                        }
                        .into(),
                    });
                    if let Some(target) = target {
                        leaders.insert(target);
                        if queued.insert(target) {
                            queue.push_back(target);
                        }
                    }
                    if flow == "conditional" {
                        leaders.insert(next);
                        edges.push(Edge {
                            from: at,
                            to: Some(next),
                            kind: "fallthrough".into(),
                        });
                        at = next;
                        continue;
                    }
                    break;
                }
                if flow == "return" {
                    edges.push(Edge {
                        from: at,
                        to: None,
                        kind: "return".into(),
                    });
                    break;
                }
                if flow == "indirect" {
                    edges.push(Edge {
                        from: at,
                        to: None,
                        kind: "indirect".into(),
                    });
                    reasons.insert(format!("unresolved indirect branch at 0x{at:x}"));
                    break;
                }
                if flow == "trap" {
                    edges.push(Edge {
                        from: at,
                        to: None,
                        kind: "trap".into(),
                    });
                    break;
                }
                at = next;
            }
            if instructions.len() >= limits.instructions
                || started.elapsed() >= Duration::from_millis(limits.milliseconds)
            {
                break;
            }
        }
        let instructions: Vec<Instruction> = instructions.into_values().collect();
        let mut blocks: Vec<BasicBlock> = vec![];
        for (i, insn) in instructions.iter().enumerate() {
            let previous = i.checked_sub(1).map(|n| &instructions[n]);
            if leaders.contains(&insn.address)
                || previous.is_none_or(|p| {
                    p.address + 4 != insn.address
                        || matches!(
                            p.flow.as_str(),
                            "branch" | "conditional" | "return" | "indirect" | "trap"
                        )
                })
            {
                blocks.push(BasicBlock {
                    address: insn.address,
                    end: insn.address + 4,
                    instruction_count: 1,
                });
            } else {
                let block = blocks.last_mut().unwrap();
                block.end = insn.address + 4;
                block.instruction_count += 1;
            }
        }
        // 分裂出来的块如果以普通指令结尾，需要显式的 fallthrough 边。
        let starts: BTreeSet<_> = blocks.iter().map(|b| b.address).collect();
        for block in &blocks {
            let last = block.end - 4;
            if let Ok(i) = instructions.binary_search_by_key(&last, |i| i.address) {
                let insn = &instructions[i];
                if matches!(insn.flow.as_str(), "linear" | "call") && starts.contains(&block.end) {
                    edges.push(Edge {
                        from: last,
                        to: Some(block.end),
                        kind: "fallthrough".into(),
                    });
                }
            }
        }
        Ok(Analysis {
            entry: address,
            instructions,
            blocks,
            edges,
            functions: functions.into_values().collect(),
            partial: !reasons.is_empty(),
            reasons: reasons.into_iter().collect(),
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
            limits,
        })
    }
}
fn relative(address: u64, value: u32, bits: u32) -> u64 {
    let signed = ((value as i64) << (64 - bits)) >> (64 - bits);
    address.wrapping_add((signed * 4) as u64)
}
fn flow(word: u32, address: u64, mnemonic: &str) -> (&'static str, Option<u64>) {
    if word & 0x7c000000 == 0x14000000 {
        return (
            if word & 0x80000000 != 0 {
                "call"
            } else {
                "branch"
            },
            Some(relative(address, word & 0x03ffffff, 26)),
        );
    }
    if word & 0xff000010 == 0x54000000 || word & 0x7e000000 == 0x34000000 {
        return (
            "conditional",
            Some(relative(address, (word >> 5) & 0x7ffff, 19)),
        );
    }
    if word & 0x7e000000 == 0x36000000 {
        return (
            "conditional",
            Some(relative(address, (word >> 5) & 0x3fff, 14)),
        );
    }
    if mnemonic.starts_with("ret") || mnemonic.starts_with("eret") {
        return ("return", None);
    }
    if mnemonic.starts_with("blr") {
        return ("call", None);
    }
    if mnemonic == "br" || mnemonic.starts_with("bra") {
        return ("indirect", None);
    }
    if matches!(mnemonic, "brk" | "hlt" | "udf") {
        return ("trap", None);
    }
    ("linear", None)
}
