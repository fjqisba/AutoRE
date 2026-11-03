// SPDX-License-Identifier: Apache-2.0
use super::{
    metadata::{Metadata, Region},
    *,
};
use capstone::{arch::arm64::Arm64OperandType, prelude::*};
use std::collections::BTreeSet;

#[derive(Clone)]
pub(crate) struct Task {
    pub address: u64,
    pub size: u64,
    pub region_start: u64,
    pub region_end: u64,
    pub code: bool,
    pub confidence: u8,
}
impl Task {
    pub fn length(&self) -> u64 {
        self.size
    }
    pub fn id(&self) -> String {
        format!(
            "{}:{:x}:{:x}",
            if self.code { "code-v1" } else { "strings-v1" },
            self.address,
            self.size
        )
    }
}
fn region_tasks(regions: &[Region], code: bool) -> impl Iterator<Item = Task> + '_ {
    let chunk = if code { 64 * 1024 } else { 256 * 1024 };
    regions.iter().flat_map(move |r| {
        (0..r.size).step_by(chunk).map(move |off| Task {
            address: r.address + off,
            size: (r.size - off).min(chunk as u64),
            region_start: r.address,
            region_end: r.address + r.size,
            code,
            confidence: r.confidence,
        })
    })
}
pub(crate) fn tasks(info: &Metadata) -> impl Iterator<Item = Task> + '_ {
    let mut code = region_tasks(&info.code, true);
    let mut data = region_tasks(&info.data, false);
    let mut choose_code = false;
    // 惰性交错产生任务；大代码段不会把首批字符串饿死，也不一次分配全部任务。
    std::iter::from_fn(move || {
        choose_code = !choose_code;
        if choose_code {
            code.next().or_else(|| data.next())
        } else {
            data.next().or_else(|| code.next())
        }
    })
}
pub(crate) fn execute(
    image: &ElfImage,
    info: &Metadata,
    task: &Task,
    cancel: &Cancellation,
) -> Result<FactBatch> {
    let mut batch = if task.code {
        code(image, info, task, cancel)?
    } else {
        strings(image, task, cancel)?
    };
    batch.checkpoint = Some((task.id(), task.size));
    Ok(batch)
}
fn signed(value: u32, bits: u32) -> i64 {
    ((value as i64) << (64 - bits)) >> (64 - bits)
}
pub(crate) fn branch(word: u32, va: u64) -> Option<(&'static str, u64)> {
    if word & 0x7c000000 == 0x14000000 {
        return Some((
            if word & 0x80000000 != 0 {
                "call"
            } else {
                "jump"
            },
            va.wrapping_add((signed(word & 0x03ffffff, 26) * 4) as u64),
        ));
    }
    if word & 0xff000010 == 0x54000000 || word & 0x7e000000 == 0x34000000 {
        return Some((
            "conditional",
            va.wrapping_add((signed((word >> 5) & 0x7ffff, 19) * 4) as u64),
        ));
    }
    if word & 0x7e000000 == 0x36000000 {
        return Some((
            "conditional",
            va.wrapping_add((signed((word >> 5) & 0x3fff, 14) * 4) as u64),
        ));
    }
    None
}
#[derive(Clone, Copy)]
enum Value {
    Address(u64),
    ImportSlot(u64),
}
fn address(value: Option<Value>) -> Option<u64> {
    match value {
        Some(Value::Address(a)) => Some(a),
        _ => None,
    }
}
fn reference(
    batch: &mut FactBatch,
    from: u64,
    to: u64,
    kind: &str,
    confidence: u8,
    evidence: &str,
) {
    batch.xrefs.push(XrefFact {
        from,
        to,
        kind: kind.into(),
        confidence,
        evidence: evidence.into(),
    });
}
fn reg_number(cs: &Capstone, reg: capstone::RegId) -> Option<usize> {
    let name = cs.reg_name(reg)?;
    match name.as_str() {
        "fp" => Some(29),
        "lr" => Some(30),
        _ => name
            .strip_prefix('x')
            .or_else(|| name.strip_prefix('w'))
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n < 31),
    }
}
fn load_pointer(image: &ElfImage, info: &Metadata, slot: u64) -> Option<Value> {
    if info.imports.contains_key(&slot) {
        return Some(Value::ImportSlot(slot));
    }
    if let Some(&target) = info.pointers.get(&slot) {
        return Some(Value::Address(target));
    }
    // 可写内存不做静态值传播；未重定位的 GOT 等位置不能当作确定指针。
    let segment = image.segment_at(slot)?;
    if segment.flags & 2 != 0 {
        return None;
    }
    let bytes = image.read_virtual(slot, 8).ok()?;
    let value = u64::from_le_bytes(bytes.try_into().ok()?);
    image.segment_at(value).map(|_| Value::Address(value))
}
fn code(
    image: &ElfImage,
    info: &Metadata,
    task: &Task,
    cancel: &Cancellation,
) -> Result<FactBatch> {
    // 分块前读 64 字节，仅用于局部寄存器上下文；输出只归属主区间。
    let start = task.address.saturating_sub(64).max(task.region_start);
    let start = (start + 3) & !3;
    let end = task.address + task.size;
    let bytes = image.read_virtual(start, (end - start) as usize)?;
    let mut leaders: BTreeSet<u64> = info.entries.range(start..end).copied().collect();
    for (i, b) in bytes.chunks_exact(4).enumerate() {
        let va = start + i as u64 * 4;
        let w = u32::from_le_bytes(b.try_into().unwrap());
        if let Some((_, target)) = branch(w, va) {
            leaders.insert(target);
            leaders.insert(va + 4);
        }
    }
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .map_err(|e| e.to_string())?;
    let mut batch = FactBatch::default();
    let mut regs = [None; 31];
    let mut pos = 0;
    while pos + 4 <= bytes.len() {
        cancel.check()?;
        let limit = (pos + 16 * 1024).min(bytes.len());
        let decoded = cs
            .disasm_all(&bytes[pos..limit], start + pos as u64)
            .map_err(|e| e.to_string())?;
        if decoded.is_empty() {
            regs.fill(None);
            pos += 4;
            continue;
        }
        for insn in decoded.iter() {
            let va = insn.address();
            if (va - start).is_multiple_of(4096) {
                cancel.check()?;
            }
            if leaders.contains(&va) {
                regs.fill(None);
            }
            let w = u32::from_le_bytes(
                insn.bytes()
                    .try_into()
                    .map_err(|_| "Unexpected instruction width")?,
            );
            let emit = va >= task.address;
            let confidence = task.confidence.min(2);
            let rd = (w & 31) as usize;
            let rn = ((w >> 5) & 31) as usize;
            if let Some((kind, target)) = branch(w, va) {
                if emit && image.executable(target) {
                    reference(
                        &mut batch,
                        va,
                        target,
                        kind,
                        confidence,
                        "direct AArch64 branch encoding in code range",
                    );
                    if kind == "call" && target & 3 == 0 && info.code_at(target) {
                        batch.functions.push(FunctionFact {
                            address: target,
                            size: 0,
                            name: format!("sub_{target:X}"),
                            source: "direct BL target (candidate)".into(),
                            confidence: 1,
                        });
                    }
                }
                regs.fill(None);
                continue;
            }
            let mnemonic = insn.mnemonic().unwrap_or("");
            if mnemonic == "br" || mnemonic.starts_with("blr") || mnemonic.starts_with("bra") {
                if emit {
                    match regs.get(rn).copied().flatten() {
                        Some(Value::Address(target)) => reference(
                            &mut batch,
                            va,
                            target,
                            if mnemonic.starts_with("blr") {
                                "indirect-call-resolved"
                            } else {
                                "indirect-jump-resolved"
                            },
                            confidence,
                            "local register value; path-sensitive refinement may be required",
                        ),
                        Some(Value::ImportSlot(slot)) => reference(
                            &mut batch,
                            va,
                            slot,
                            "import-dispatch",
                            confidence,
                            "register loaded from relocation-backed import slot",
                        ),
                        None => reference(
                            &mut batch,
                            va,
                            va,
                            "unresolved-indirect",
                            0,
                            "target unknown; destination stores site identity, not a target",
                        ),
                    }
                }
                regs.fill(None);
                continue;
            }
            if mnemonic.starts_with("ret")
                || mnemonic.starts_with("eret")
                || matches!(mnemonic, "brk" | "hlt" | "udf")
            {
                regs.fill(None);
                continue;
            }
            let old = regs;
            let mut assigned = None;
            // 使用结构化读写信息清除未知写入，包括 Wn 写入和 pre/post-index 写回。
            match cs.insn_detail(insn) {
                Ok(detail) => {
                    for reg in detail.regs_write() {
                        if let Some(n) = reg_number(&cs, *reg) {
                            regs[n] = None;
                        }
                    }
                    let arch = detail.arch_detail();
                    if let Some(arm) = arch.arm64() {
                        for op in arm.operands() {
                            match op.op_type {
                                Arm64OperandType::Reg(reg)
                                    if op.access.is_some_and(|a| a.is_writable()) =>
                                {
                                    if let Some(n) = reg_number(&cs, reg) {
                                        regs[n] = None;
                                    }
                                }
                                Arm64OperandType::Mem(mem) if arm.writeback() => {
                                    if let Some(n) = reg_number(&cs, mem.base()) {
                                        regs[n] = None;
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
                Err(_) => {
                    regs.fill(None);
                }
            }
            if w & 0x1f000000 == 0x10000000 {
                let delta = signed(((w >> 5) & 0x7ffff) << 2 | ((w >> 29) & 3), 21);
                let target = if w & 0x80000000 != 0 {
                    (va & !4095).wrapping_add((delta * 4096) as u64)
                } else {
                    va.wrapping_add(delta as u64)
                };
                assigned = Some(Value::Address(target));
                // ADRP 页基址不是具体字符串引用。
                if emit && w & 0x80000000 == 0 && image.segment_at(target).is_some() {
                    reference(
                        &mut batch,
                        va,
                        target,
                        "address",
                        confidence,
                        "ADR PC-relative address",
                    );
                }
            } else if w & 0x7f000000 == 0x11000000 {
                if let Some(base) = old
                    .get(rn)
                    .copied()
                    .flatten()
                    .and_then(|v| address(Some(v)))
                {
                    let imm =
                        (((w >> 10) & 4095) as u64) << if w & (1 << 22) != 0 { 12 } else { 0 };
                    let value = base.wrapping_add(imm);
                    let value = if w >> 31 == 0 {
                        value & 0xffff_ffff
                    } else {
                        value
                    };
                    assigned = Some(Value::Address(value));
                    if emit && image.segment_at(value).is_some() {
                        reference(
                            &mut batch,
                            va,
                            value,
                            "address",
                            confidence,
                            "local ADRP/constant + ADD immediate",
                        );
                    }
                }
            } else if w & 0x1f800000 == 0x12800000 {
                let shift = ((w >> 21) & 3) * 16;
                let imm = ((w >> 5) & 0xffff) as u64;
                let opc = (w >> 29) & 3;
                let value = match opc {
                    2 => Some(imm << shift),
                    0 => Some(!(imm << shift)),
                    3 => old
                        .get(rd)
                        .copied()
                        .flatten()
                        .and_then(|v| address(Some(v)))
                        .map(|v| (v & !(0xffffu64 << shift)) | (imm << shift)),
                    _ => None,
                };
                assigned =
                    value.map(|v| Value::Address(if w >> 31 == 0 { v & 0xffff_ffff } else { v }));
            } else if w & 0x7fe0ffe0 == 0x2a0003e0 {
                let rm = ((w >> 16) & 31) as usize;
                assigned = old.get(rm).copied().flatten();
                if w >> 31 == 0 {
                    assigned = address(assigned).map(|v| Value::Address(v & 0xffff_ffff));
                }
            } else if w & 0x3b000000 == 0x39000000 && w & (1 << 26) == 0 {
                let scale = w >> 30;
                let opc = (w >> 22) & 3;
                if let Some(base) = old
                    .get(rn)
                    .copied()
                    .flatten()
                    .and_then(|v| address(Some(v)))
                {
                    let target = base.wrapping_add((((w >> 10) & 4095) as u64) << scale);
                    if emit && image.segment_at(target).is_some() {
                        reference(
                            &mut batch,
                            va,
                            target,
                            if opc == 0 { "write" } else { "read" },
                            confidence,
                            "local base + unsigned scaled load/store offset",
                        );
                    }
                    if opc == 1 && scale == 3 {
                        assigned = load_pointer(image, info, target);
                    }
                }
            } else if w & 0x3b000000 == 0x18000000 && w & (1 << 26) == 0 {
                let target = va.wrapping_add((signed((w >> 5) & 0x7ffff, 19) * 4) as u64);
                if (w >> 30) != 3 && emit && image.segment_at(target).is_some() {
                    reference(&mut batch, va, target, "read", confidence, "LDR literal");
                }
                if w >> 30 == 1 {
                    assigned = load_pointer(image, info, target);
                }
            }
            if rd < 31 {
                if let Some(v) = assigned {
                    regs[rd] = Some(v);
                }
            }
        }
        pos += decoded.iter().map(|i| i.bytes().len()).sum::<usize>();
    }
    Ok(batch)
}
fn ascii_byte(b: u8) -> bool {
    b >= 32 && b != 127 || matches!(b, 9 | 10 | 13)
}
fn text_valid(text: &str) -> bool {
    text.chars().count() >= 4
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        && text.chars().any(|c| !c.is_whitespace())
}
fn strings(image: &ElfImage, task: &Task, cancel: &Cancellation) -> Result<FactBatch> {
    let start = task.address.saturating_sub(4).max(task.region_start);
    let end = (task.address + task.size + 16384).min(task.region_end);
    let bytes = image.read_virtual(start, (end - start) as usize)?;
    let mut batch = FactBatch::default();
    let mut i = 0;
    while i < bytes.len() {
        if i % 4096 == 0 {
            cancel.check()?;
        }
        if !ascii_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let first = i;
        while i < bytes.len() && ascii_byte(bytes[i]) {
            i += 1;
        }
        let va = start + first as u64;
        if va < task.address || va >= task.address + task.size {
            continue;
        }
        let terminated = bytes.get(i) == Some(&0);
        let truncated = i == bytes.len();
        if truncated && end < task.region_end && va >= task.address && va < task.address + task.size
        {
            batch.warnings.push(format!(
                "String at {va:#x} exceeds chunk continuation budget; extent is partial"
            ));
        }
        if !terminated && !truncated {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(&bytes[first..i]) {
            if text_valid(text) {
                batch.strings.push(StringFact {
                    address: va,
                    end: start + i as u64,
                    encoding: if text.is_ascii() { "ASCII" } else { "UTF-8" }.into(),
                    text: text.chars().take(1024).collect(),
                    truncated: truncated || text.chars().count() > 1024,
                    source: if task.confidence > 1 {
                        "allocated data"
                    } else {
                        "unclassified mapping (candidate)"
                    }
                    .into(),
                });
            }
        } else if let Err(error) = std::str::from_utf8(&bytes[first..i]) {
            i = first + error.valid_up_to() + error.error_len().unwrap_or(1);
        }
    }
    let mut i = if start & 1 != 0 { 1 } else { 0 };
    while i + 1 < bytes.len() {
        if i % 4096 == 0 {
            cancel.check()?;
        }
        let mut units = Vec::new();
        let first = i;
        while i + 1 < bytes.len() {
            let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if unit == 0 || unit < 32 && !matches!(unit, 9 | 10 | 13) {
                break;
            }
            units.push(unit);
            i += 2;
        }
        let va = start + first as u64;
        let terminated = i + 1 < bytes.len() && bytes[i] == 0 && bytes[i + 1] == 0;
        let truncated = i + 1 >= bytes.len();
        if truncated && end < task.region_end && va >= task.address && va < task.address + task.size
        {
            batch.warnings.push(format!(
                "UTF-16 candidate at {va:#x} exceeds chunk continuation budget; extent is partial"
            ));
        }
        if (terminated || truncated)
            && va >= task.address
            && va < task.address + task.size
            && units.len() >= 4
        {
            if let Ok(text) = String::from_utf16(&units) {
                // 缺乏类型信息时要求至少一半单元为常见可读字符，避免随机指针误识别。
                let familiar = text
                    .chars()
                    .filter(|c| {
                        c.is_ascii_alphanumeric()
                            || c.is_ascii_punctuation()
                            || c.is_ascii_whitespace()
                    })
                    .count();
                let han = text
                    .chars()
                    .filter(|c| ('\u{4e00}'..='\u{9fff}').contains(c))
                    .count();
                if text_valid(&text)
                    && (familiar * 4 >= text.chars().count() * 3
                        || han >= 4 && han == text.chars().count())
                {
                    batch.strings.push(StringFact {
                        address: va,
                        end: start + i as u64,
                        encoding: "UTF-16LE".into(),
                        text: text.chars().take(1024).collect(),
                        truncated: truncated || text.chars().count() > 1024,
                        source: "data text candidate".into(),
                    });
                }
            }
        }
        i += 2;
    }
    Ok(batch)
}
