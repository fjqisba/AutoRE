// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
};

#[derive(Clone, Debug)]
pub(crate) struct Region {
    pub address: u64,
    pub size: u64,
    pub confidence: u8,
}
#[derive(Default)]
pub(crate) struct Metadata {
    pub code: Vec<Region>,
    pub data: Vec<Region>,
    pub entries: BTreeSet<u64>,
    pub pointers: BTreeMap<u64, u64>,
    pub imports: BTreeMap<u64, String>,
    pub warnings: Vec<String>,
    mapping: BTreeMap<u64, bool>,
}
impl Metadata {
    pub fn code_at(&self, va: u64) -> bool {
        self.code
            .iter()
            .any(|r| va >= r.address && va < r.address.saturating_add(r.size))
    }
}
#[derive(Clone)]
struct Symbol {
    name: String,
    address: u64,
    defined: bool,
}
/// 元数据小读复用 64 KiB 页，避免每个符号名一次系统调用。缓存固定 1 MiB。
struct Reader<'a> {
    image: &'a ElfImage,
    pages: RefCell<VecDeque<(u64, Vec<u8>)>>,
}
impl<'a> Reader<'a> {
    fn new(image: &'a ElfImage) -> Self {
        Self {
            image,
            pages: RefCell::new(VecDeque::new()),
        }
    }
    fn bytes(&self, va: u64, len: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(len);
        let mut at = va;
        while result.len() < len {
            let off = self
                .image
                .file_offset(at)
                .ok_or("Metadata address has no file-backed mapping")?;
            let base = off & !65535;
            let mut pages = self.pages.borrow_mut();
            if !pages.iter().any(|(b, _)| *b == base) {
                let data = self
                    .image
                    .read_file(base, (self.image.length - base).min(65536) as usize)?;
                if pages.len() == 16 {
                    pages.pop_front();
                }
                pages.push_back((base, data));
            }
            let data = &pages.iter().find(|(b, _)| *b == base).unwrap().1;
            let pos = (off - base) as usize;
            let segment = self.image.segment_at(at).ok_or("Unmapped metadata")?;
            let n = (len - result.len())
                .min(data.len() - pos)
                .min((segment.file_size - (at - segment.address)) as usize);
            if n == 0 {
                return Err("Metadata read made no progress".into());
            }
            result.extend_from_slice(&data[pos..pos + n]);
            at = at.checked_add(n as u64).ok_or("Metadata VA overflow")?;
        }
        Ok(result)
    }
    fn u32(&self, va: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(va, 4)?.try_into().unwrap()))
    }
    fn u64(&self, va: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(va, 8)?.try_into().unwrap()))
    }
    fn string(&self, base: u64, len: u64, index: u64) -> Result<String> {
        if index >= len {
            return Err("Symbol name outside string table".into());
        }
        let bytes = self.bytes(
            base.checked_add(index).ok_or("String VA overflow")?,
            (len - index).min(4096) as usize,
        )?;
        let n = bytes
            .iter()
            .position(|b| *b == 0)
            .ok_or("Symbol name exceeds 4096-byte budget")?;
        Ok(String::from_utf8_lossy(&bytes[..n])
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect())
    }
}
fn u64at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn u32at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn function(va: u64, size: u64, name: String, source: &str, confidence: u8) -> FunctionFact {
    FunctionFact {
        address: va,
        size,
        name,
        source: source.into(),
        confidence,
    }
}

pub(crate) fn discover(
    image: &ElfImage,
    cancel: &Cancellation,
    publish: &mut impl FnMut(FactBatch) -> Result<()>,
) -> Result<Metadata> {
    let reader = Reader::new(image);
    let mut info = Metadata::default();
    let mut batch = FactBatch::default();
    let sections = match image.sections(cancel) {
        Ok(s) => s,
        Err(e) => {
            info.warnings.push(format!("Section table: {e}"));
            vec![]
        }
    };
    for s in &sections {
        if s.flags & 2 == 0 || s.kind == 8 || s.size == 0 {
            continue;
        }
        if s.address.checked_add(s.size).is_none() || image.file_offset(s.address) != Some(s.offset)
        {
            info.warnings
                .push(format!("Unmapped allocated section at {:x}", s.address));
            continue;
        }
        let region = Region {
            address: s.address,
            size: s.size,
            confidence: if s.flags & 4 != 0 { 2 } else { 3 },
        };
        if s.flags & 4 != 0 {
            info.code.push(region);
        } else if s.kind == 1
            && !matches!(
                s.name.as_str(),
                ".eh_frame" | ".eh_frame_hdr" | ".gcc_except_table" | ".interp"
            )
            && !s.name.starts_with(".debug")
        {
            info.data.push(region);
        }
    }
    let mut dynamic = BTreeMap::new();
    for seg in image.segments.iter().filter(|s| s.kind == 2) {
        let count = (seg.file_size / 16).min(65536);
        let mut terminated = false;
        for i in 0..count {
            cancel.check()?;
            let b = image.read_file(seg.offset + i * 16, 16)?;
            let tag = u64at(&b, 0);
            if tag == 0 {
                terminated = true;
                break;
            }
            dynamic.insert(tag, u64at(&b, 8));
        }
        if !terminated {
            info.warnings
                .push("Dynamic table missing terminator or exceeded budget".into());
        }
    }
    let mut dyn_symbols = BTreeMap::<u64, Symbol>::new();
    // 不加载整个字符串表；以偏移定位，名称页缓存供同表符号共享。
    for s in sections.iter().filter(|s| s.kind == 2 || s.kind == 11) {
        if s.entry_size < 24 || s.entry_size > 1024 || s.size % s.entry_size != 0 {
            info.warnings.push("Invalid symbol table layout".into());
            continue;
        }
        let Some(strings) = sections.get(s.link as usize) else {
            info.warnings.push("Symbol string table missing".into());
            continue;
        };
        let mut file_names = Vec::new();
        // 非分配 .symtab/.strtab 不能经 VA 读取，按表的真实文件偏移处理。
        if strings.flags & 2 == 0 {
            if strings.size > 64 * 1024 * 1024 {
                info.warnings
                    .push("Nonallocated string table exceeds 64 MiB budget".into());
                continue;
            }
            let mut off = 0;
            while off < strings.size {
                cancel.check()?;
                let b = image.read_file(
                    strings.offset + off,
                    (strings.size - off).min(1024 * 1024) as usize,
                )?;
                off += b.len() as u64;
                file_names.extend(b);
            }
        }
        let count = s.size / s.entry_size;
        if count > 2_000_000 {
            info.warnings
                .push("Symbol table exceeds two million entries; remainder not indexed".into());
        }
        let per = (65536 / s.entry_size).max(1);
        let mut start = 0;
        while start < count.min(2_000_000) {
            cancel.check()?;
            let n = (count.min(2_000_000) - start).min(per);
            let bytes =
                image.read_file(s.offset + start * s.entry_size, (n * s.entry_size) as usize)?;
            for (i, b) in bytes.chunks_exact(s.entry_size as usize).enumerate() {
                let offset = u32at(b, 0) as u64;
                let name = if strings.flags & 2 != 0 {
                    reader.string(strings.address, strings.size, offset)
                } else {
                    file_names
                        .get(offset as usize..)
                        .and_then(|v| {
                            v.iter()
                                .take(4096)
                                .position(|b| *b == 0)
                                .map(|n| String::from_utf8_lossy(&v[..n]).into_owned())
                        })
                        .ok_or_else(|| "Bad symbol string offset".into())
                };
                let name = match name {
                    Ok(n) => n,
                    Err(e) => {
                        if info.warnings.len() < 32 {
                            info.warnings.push(e);
                        }
                        continue;
                    }
                };
                let sym = consume_symbol(
                    image,
                    b,
                    name,
                    if s.kind == 11 { ".dynsym" } else { ".symtab" },
                    &mut info,
                    &mut batch,
                );
                if s.kind == 11 {
                    dyn_symbols.insert(start + i as u64, sym);
                }
            }
            publish(std::mem::take(&mut batch))?;
            start += n;
        }
    }
    if dyn_symbols.is_empty() {
        if let (Some(&symtab), Some(&strtab), Some(&strsz)) =
            (dynamic.get(&6), dynamic.get(&5), dynamic.get(&10))
        {
            let entry = dynamic.get(&11).copied().unwrap_or(24);
            let count = dynamic_count(&reader, &dynamic, cancel);
            match count {
                Ok(count) if (24..=1024).contains(&entry) => {
                    for i in 0..count {
                        cancel.check()?;
                        let b = reader.bytes(
                            symtab
                                .checked_add(i.checked_mul(entry).ok_or("Symbol table overflow")?)
                                .ok_or("Symbol table overflow")?,
                            24,
                        )?;
                        let name = reader.string(strtab, strsz, u32at(&b, 0) as u64)?;
                        let sym =
                            consume_symbol(image, &b, name, "PT_DYNAMIC", &mut info, &mut batch);
                        dyn_symbols.insert(i, sym);
                        if i % 1024 == 1023 {
                            publish(std::mem::take(&mut batch))?;
                        }
                    }
                }
                Ok(_) => info.warnings.push("Invalid DT_SYMENT".into()),
                Err(e) => info.warnings.push(e),
            }
        }
    }
    publish(std::mem::take(&mut batch))?;
    if image.entry != 0 && image.executable(image.entry) {
        info.entries.insert(image.entry);
        batch.functions.push(function(
            image.entry,
            0,
            "entry_point".into(),
            "ELF entry",
            3,
        ));
    }
    if let Err(e) = unwind(&reader, &sections, &mut info, &mut batch, cancel, publish) {
        cancel.check()?;
        info.warnings.push(format!("Unwind: {e}"));
    }
    publish(std::mem::take(&mut batch))?;
    // 动态重定位是无 section 文件的首选来源；地址直接归一为 ELF VA。
    let mut relocations = Vec::new();
    for (tag, size_tag, entry_tag, rela) in [(7, 8, 9, true), (17, 18, 19, false)] {
        if let (Some(&base), Some(&size)) = (dynamic.get(&tag), dynamic.get(&size_tag)) {
            relocations.push((
                base,
                size,
                dynamic
                    .get(&entry_tag)
                    .copied()
                    .unwrap_or(if rela { 24 } else { 16 }),
                rela,
            ));
        }
    }
    if let (Some(&base), Some(&size)) = (dynamic.get(&23), dynamic.get(&2)) {
        let rela = dynamic.get(&20) == Some(&7);
        relocations.push((base, size, if rela { 24 } else { 16 }, rela));
    }
    for (base, size, entry, rela) in relocations {
        let min = if rela { 24 } else { 16 };
        if entry < min || entry > 1024 || size % entry != 0 {
            info.warnings
                .push("Invalid dynamic relocation table".into());
            continue;
        }
        if size / entry > 2_000_000 {
            info.warnings
                .push("Relocation budget exceeded; remaining references unknown".into());
        }
        for i in 0..(size / entry).min(2_000_000) {
            cancel.check()?;
            let b = reader.bytes(
                base.checked_add(i * entry).ok_or("Relocation overflow")?,
                min as usize,
            )?;
            let slot = u64at(&b, 0);
            let rinfo = u64at(&b, 8);
            let addend = if rela {
                u64at(&b, 16)
            } else {
                reader.u64(slot)?
            };
            relocation(
                image,
                slot,
                rinfo,
                addend,
                &dyn_symbols,
                &mut info,
                &mut batch,
            );
            if i % 1024 == 1023 {
                publish(std::mem::take(&mut batch))?;
            }
        }
    }
    for (tag, size_tag, rela) in [
        (0x60000011, 0x60000012, true),
        (0x6000000f, 0x60000010, false),
    ] {
        if let (Some(&base), Some(&size)) = (dynamic.get(&tag), dynamic.get(&size_tag)) {
            if let Err(e) = packed(
                &reader,
                base,
                size,
                rela,
                &dyn_symbols,
                &mut info,
                &mut batch,
                cancel,
                publish,
            ) {
                cancel.check()?;
                info.warnings
                    .push(format!("Android packed relocations: {e}"));
            }
        }
    }
    for (tag, size_tag) in [(36, 35), (0x6fffe000, 0x6fffe001)] {
        if let (Some(&base), Some(&size)) = (dynamic.get(&tag), dynamic.get(&size_tag)) {
            if let Err(e) = relr(
                &reader,
                base,
                size,
                &dyn_symbols,
                &mut info,
                &mut batch,
                cancel,
                publish,
            ) {
                cancel.check()?;
                info.warnings.push(format!("RELR: {e}"));
            }
        }
    }
    for tag in [12, 13] {
        if let Some(&va) = dynamic.get(&tag) {
            if va != 0 && image.executable(va) {
                info.entries.insert(va);
                batch.functions.push(function(
                    va,
                    0,
                    format!("init_fini_{va:X}"),
                    "DT_INIT/FINI",
                    3,
                ));
            }
        }
    }
    for (tag, size_tag) in [(25, 27), (26, 28), (32, 33)] {
        if let (Some(&va), Some(&size)) = (dynamic.get(&tag), dynamic.get(&size_tag)) {
            if size / 8 > 65536 {
                info.warnings
                    .push("Init/fini array exceeds entry budget".into());
            }
            for i in 0..(size / 8).min(65536) {
                cancel.check()?;
                let slot = va + i * 8;
                let target = info
                    .pointers
                    .get(&slot)
                    .copied()
                    .unwrap_or(reader.u64(slot)?);
                if target != 0 && target != u64::MAX && image.executable(target) {
                    info.entries.insert(target);
                    batch.functions.push(function(
                        target,
                        0,
                        format!("init_{target:X}"),
                        "init/fini array",
                        3,
                    ));
                    batch.xrefs.push(XrefFact {
                        from: slot,
                        to: target,
                        kind: "initializer".into(),
                        confidence: 3,
                        evidence: "ELF initializer pointer (relocation overlay)".into(),
                    });
                }
            }
        }
    }
    publish(batch)?;
    if info.code.is_empty() {
        // 无 section 时只把已知函数范围视为强代码，剩余执行映射显式作为候选。
        info.code = image
            .segments
            .iter()
            .filter(|s| s.executable())
            .map(|s| Region {
                address: s.address,
                size: s.file_size,
                confidence: 1,
            })
            .collect();
        info.warnings.push("No executable section ranges: raw executable mappings scanned as candidates; code/data classification incomplete".into());
    }
    if sections.is_empty() || info.data.is_empty() {
        info.data = image
            .segments
            .iter()
            .filter(|s| s.loadable() && (sections.is_empty() || !s.executable()))
            .map(|s| Region {
                address: s.address,
                size: s.file_size,
                confidence: 1,
            })
            .collect();
    }
    // $x/$d 是区间分类证据；从代码区剔除 literal pool，数据仍参与字符串识别。
    let mut code = Vec::new();
    for region in &info.code {
        let end = region.address.saturating_add(region.size);
        let mut start = region.address;
        let mut executable = true;
        for (&at, &is_code) in info.mapping.range(region.address..end) {
            if at > start {
                let part = Region {
                    address: start,
                    size: at - start,
                    confidence: region.confidence,
                };
                if executable {
                    code.push(part);
                } else {
                    info.data.push(part);
                }
            }
            start = at;
            executable = is_code;
        }
        if start < end {
            let part = Region {
                address: start,
                size: end - start,
                confidence: region.confidence,
            };
            if executable {
                code.push(part);
            } else {
                info.data.push(part);
            }
        }
    }
    info.code = code;
    info.code.sort_by_key(|r| r.address);
    info.data.sort_by_key(|r| r.address);
    Ok(info)
}

fn consume_symbol(
    image: &ElfImage,
    b: &[u8],
    name: String,
    source: &str,
    info: &mut Metadata,
    batch: &mut FactBatch,
) -> Symbol {
    let va = u64at(b, 8);
    let size = u64at(b, 16);
    let kind = b[4] & 15;
    let binding = b[4] >> 4;
    let defined = u16::from_le_bytes([b[6], b[7]]) != 0;
    if defined && (name == "$x" || name.starts_with("$x.")) {
        info.mapping.insert(va, true);
    }
    if defined && (name == "$d" || name.starts_with("$d.")) {
        info.mapping.insert(va, false);
    }
    if defined && (kind == 2 || kind == 10) && image.executable(va) {
        info.entries.insert(va);
        batch.functions.push(function(
            va,
            if va.checked_add(size).is_some() {
                size
            } else {
                0
            },
            if name.is_empty() {
                format!("sub_{va:X}")
            } else {
                name.clone()
            },
            if kind == 10 { "IFUNC resolver" } else { source },
            if name == "JNI_OnLoad" { 5 } else { 4 },
        ));
    }
    if !name.is_empty() && binding != 0 && defined {
        batch.symbols.push(SymbolFact {
            address: va,
            name: name.clone(),
            kind: "export".into(),
            source: source.into(),
        });
        // imports 按实际重定位槽位记录，避免所有未定义符号都挤在地址零。
    }
    Symbol {
        name,
        address: va,
        defined,
    }
}
fn dynamic_count(
    reader: &Reader<'_>,
    tags: &BTreeMap<u64, u64>,
    cancel: &Cancellation,
) -> Result<u64> {
    if let Some(&base) = tags.get(&4) {
        let count = reader.u32(base + 4)? as u64;
        if count > 2_000_000 {
            return Err("DT_HASH symbol count exceeds budget".into());
        }
        return Ok(count);
    }
    let base = *tags
        .get(&0x6ffffef5)
        .ok_or("No symbol section or HASH/GNU_HASH: dynamic symbol coverage unknown")?;
    let buckets = reader.u32(base)? as u64;
    let start = reader.u32(base + 4)? as u64;
    let bloom = reader.u32(base + 8)? as u64;
    if buckets > 2_000_000 || bloom > 2_000_000 || start > 2_000_000 {
        return Err("Invalid GNU_HASH dimensions".into());
    }
    let bbase = base
        .checked_add(16 + bloom * 8)
        .ok_or("GNU_HASH overflow")?;
    let chains = bbase.checked_add(buckets * 4).ok_or("GNU_HASH overflow")?;
    let mut last = 0;
    for i in 0..buckets {
        cancel.check()?;
        last = last.max(reader.u32(bbase + i * 4)? as u64);
    }
    if last == 0 {
        return Ok(start);
    }
    if last < start || last > 2_000_000 {
        return Err("Invalid GNU_HASH bucket".into());
    }
    loop {
        cancel.check()?;
        if last >= 2_000_000 {
            return Err("GNU_HASH chain budget exceeded".into());
        }
        let value = reader.u32(chains + (last - start) * 4)?;
        last += 1;
        if value & 1 != 0 {
            return Ok(last);
        }
    }
}
fn relocation(
    image: &ElfImage,
    slot: u64,
    rinfo: u64,
    addend: u64,
    symbols: &BTreeMap<u64, Symbol>,
    info: &mut Metadata,
    batch: &mut FactBatch,
) {
    let kind = rinfo as u32;
    let symbol = symbols.get(&(rinfo >> 32));
    if image.segment_at(slot).is_none() {
        return;
    }
    let target = match kind {
        1027 => Some(addend),
        257 | 1025 | 1026 => symbol
            .filter(|s| s.defined)
            .map(|s| s.address.wrapping_add(addend)),
        _ => None,
    };
    if let Some(target) = target.filter(|t| image.segment_at(*t).is_some()) {
        info.pointers.insert(slot, target);
        batch.xrefs.push(XrefFact {
            from: slot,
            to: target,
            kind: "pointer".into(),
            confidence: 3,
            evidence: format!("AArch64 relocation {kind}"),
        });
        if image.executable(target)
            && (info.code_at(target) || info.code.is_empty())
            && target & 3 == 0
        {
            info.entries.insert(target);
            batch.functions.push(function(
                target,
                0,
                format!("sub_{target:X}"),
                "relocated code pointer (candidate)",
                1,
            ));
        }
    } else if let Some(s) = symbol.filter(|s| !s.defined && !s.name.is_empty()) {
        info.imports.insert(slot, s.name.clone());
        batch.symbols.push(SymbolFact {
            address: slot,
            name: s.name.clone(),
            kind: "import".into(),
            source: format!("relocation {kind}; external binding unresolved"),
        });
    }
}
fn encoded(reader: &Reader<'_>, at: &mut u64, encoding: u8, data_base: u64) -> Result<u64> {
    if encoding == 0xff {
        return Err("Omitted EH encoding".into());
    }
    let field = *at;
    let (value, len) = match encoding & 15 {
        0 => (reader.u64(*at)?, 8),
        3 => (reader.u32(*at)? as u64, 4),
        0x0b => (reader.u32(*at)? as i32 as i64 as u64, 4),
        4 | 0x0c => (reader.u64(*at)?, 8),
        _ => return Err(format!("Unsupported EH pointer encoding {encoding:#x}")),
    };
    *at = at.checked_add(len).ok_or("EH pointer overflow")?;
    let value = match encoding & 0x70 {
        0 => value,
        0x10 => field.wrapping_add(value),
        0x30 => data_base.wrapping_add(value),
        _ => return Err("Unsupported EH relative base".into()),
    };
    if encoding & 0x80 != 0 {
        reader.u64(value)
    } else {
        Ok(value)
    }
}
fn unwind(
    reader: &Reader<'_>,
    sections: &[crate::elf::Section],
    info: &mut Metadata,
    batch: &mut FactBatch,
    cancel: &Cancellation,
    publish: &mut impl FnMut(FactBatch) -> Result<()>,
) -> Result<()> {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};
    let Some(header) = reader.image.segments.iter().find(|s| s.kind == 0x6474e550) else {
        return Ok(());
    };
    let h = reader.bytes(header.address, 4)?;
    if h[0] != 1 {
        return Err("Unsupported EH header version".into());
    }
    let mut at = header.address + 4;
    let frame_va = encoded(reader, &mut at, h[1], header.address)?;
    let size = sections
        .iter()
        .find(|s| s.address == frame_va && s.kind != 8)
        .map(|s| s.size)
        .or_else(|| {
            reader
                .image
                .segment_at(frame_va)
                .map(|s| s.file_size.saturating_sub(frame_va - s.address))
        })
        .ok_or("EH frame unmapped")?;
    if size > 64 * 1024 * 1024 {
        return Err("EH frame read exceeds 64 MiB budget".into());
    }
    let mut bytes = Vec::with_capacity(size as usize);
    let mut offset = 0;
    while offset < size {
        cancel.check()?;
        let b = reader
            .image
            .read_virtual(frame_va + offset, (size - offset).min(1024 * 1024) as usize)?;
        offset += b.len() as u64;
        bytes.extend(b);
    }
    let mut frame = EhFrame::new(&bytes, LittleEndian);
    frame.set_address_size(8);
    let bases = BaseAddresses::default()
        .set_eh_frame(frame_va)
        .set_eh_frame_hdr(header.address);
    let mut entries = frame.entries(&bases);
    while let Some(entry) = entries.next().map_err(|e| e.to_string())? {
        cancel.check()?;
        if let CieOrFde::Fde(partial) = entry {
            let fde = partial
                .parse(EhFrame::cie_from_offset)
                .map_err(|e| e.to_string())?;
            let va = fde.initial_address();
            let size = fde.len();
            if va & 3 == 0
                && reader.image.executable(va)
                && size > 0
                && va.checked_add(size).is_some()
            {
                info.entries.insert(va);
                batch.functions.push(function(
                    va,
                    size,
                    format!("sub_{va:X}"),
                    ".eh_frame FDE range",
                    3,
                ));
            }
            if batch.functions.len() >= 1024 {
                publish(std::mem::take(batch))?;
            }
        }
    }
    Ok(())
}
fn sleb(bytes: &[u8], cursor: &mut usize) -> Result<i64> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        let b = *bytes.get(*cursor).ok_or("Truncated packed SLEB128")?;
        *cursor += 1;
        if shift == 63 && b != 0 && b != 0x7f {
            return Err("SLEB128 overflow".into());
        }
        result |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && b & 0x40 != 0 {
                result |= u64::MAX << shift;
            }
            return Ok(result as i64);
        }
        if shift >= 64 {
            return Err("SLEB128 overflow".into());
        }
    }
}
#[allow(clippy::too_many_arguments)] // 格式参数与共享事实输出分别传入，避免隐藏可变全局状态。
fn packed(
    reader: &Reader<'_>,
    base: u64,
    size: u64,
    rela: bool,
    symbols: &BTreeMap<u64, Symbol>,
    info: &mut Metadata,
    batch: &mut FactBatch,
    cancel: &Cancellation,
    publish: &mut impl FnMut(FactBatch) -> Result<()>,
) -> Result<()> {
    if size > 32 * 1024 * 1024 {
        return Err("Packed relocation table exceeds 32 MiB budget".into());
    }
    let bytes = reader.bytes(base, size as usize)?;
    if bytes.get(..4) != Some(b"APS2") {
        return Err("Missing APS2 header".into());
    }
    let mut cursor = 4;
    let count = sleb(&bytes, &mut cursor)?;
    if !(0..=2_000_000).contains(&count) {
        return Err("Packed relocation count invalid".into());
    }
    let mut offset = sleb(&bytes, &mut cursor)?;
    let mut addend = 0i64;
    let mut done = 0;
    while done < count {
        cancel.check()?;
        let n = sleb(&bytes, &mut cursor)?;
        let flags = sleb(&bytes, &mut cursor)?;
        if n <= 0 || n > count - done || flags & !15 != 0 {
            return Err("Invalid packed relocation group".into());
        }
        let delta = if flags & 2 != 0 {
            sleb(&bytes, &mut cursor)?
        } else {
            0
        };
        let group_info = if flags & 1 != 0 {
            sleb(&bytes, &mut cursor)?
        } else {
            0
        };
        let group_add = if flags & 8 != 0 && flags & 4 != 0 {
            sleb(&bytes, &mut cursor)?
        } else {
            0
        };
        if !rela && flags & 8 != 0 {
            return Err("REL group contains explicit addends".into());
        }
        for _ in 0..n {
            cancel.check()?;
            offset = offset
                .checked_add(if flags & 2 != 0 {
                    delta
                } else {
                    sleb(&bytes, &mut cursor)?
                })
                .ok_or("Packed relocation offset overflow")?;
            let rinfo = if flags & 1 != 0 {
                group_info
            } else {
                sleb(&bytes, &mut cursor)?
            };
            if flags & 8 != 0 {
                addend = addend
                    .checked_add(if flags & 4 != 0 {
                        group_add
                    } else {
                        sleb(&bytes, &mut cursor)?
                    })
                    .ok_or("Packed relocation addend overflow")?;
            } else {
                addend = 0;
            }
            let slot = u64::try_from(offset).map_err(|_| "Negative relocation offset")?;
            relocation(
                reader.image,
                slot,
                rinfo as u64,
                if rela {
                    addend as u64
                } else {
                    reader.u64(slot)?
                },
                symbols,
                info,
                batch,
            );
            done += 1;
            if done % 1024 == 0 {
                publish(std::mem::take(batch))?;
            }
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn relr(
    reader: &Reader<'_>,
    base: u64,
    size: u64,
    symbols: &BTreeMap<u64, Symbol>,
    info: &mut Metadata,
    batch: &mut FactBatch,
    cancel: &Cancellation,
    publish: &mut impl FnMut(FactBatch) -> Result<()>,
) -> Result<()> {
    if !size.is_multiple_of(8) || size / 8 > 2_000_000 {
        return Err("Invalid/oversized RELR table".into());
    }
    let mut next = None;
    let mut expanded = 0;
    for i in 0..size / 8 {
        cancel.check()?;
        let entry = reader.u64(base + i * 8)?;
        let mut slots = Vec::new();
        if entry & 1 == 0 {
            slots.push(entry);
            next = entry.checked_add(8);
        } else {
            let at = next.ok_or("RELR bitmap without base")?;
            for bit in 1..64 {
                if entry & (1u64 << bit) != 0 {
                    slots.push(at.checked_add((bit - 1) * 8).ok_or("RELR overflow")?);
                }
            }
            next = at.checked_add(63 * 8);
        }
        for slot in slots {
            expanded += 1;
            if expanded > 2_000_000 {
                return Err("Expanded RELR budget exceeded".into());
            }
            relocation(
                reader.image,
                slot,
                1027,
                reader.u64(slot)?,
                symbols,
                info,
                batch,
            );
        }
        if batch.xrefs.len() >= 1024 {
            publish(std::mem::take(batch))?;
        }
    }
    Ok(())
}
