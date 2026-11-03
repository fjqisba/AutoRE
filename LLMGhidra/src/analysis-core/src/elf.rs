// SPDX-License-Identifier: Apache-2.0
use crate::{Cancellation, Result};
use serde::Serialize;
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_TABLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_READ: usize = 1024 * 1024;
const MAX_SYMBOLS: usize = 200_000;

#[derive(Clone, Debug, Serialize)]
pub struct Segment {
    pub index: u32,
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}
impl Segment {
    pub fn end(&self) -> u64 {
        self.address + self.memory_size
    }
    pub fn loadable(&self) -> bool {
        self.kind == 1
    }
    pub fn executable(&self) -> bool {
        self.loadable() && self.flags & 1 != 0
    }
    pub fn permissions(&self) -> String {
        format!(
            "{}{}{}",
            if self.flags & 4 != 0 { "R" } else { "-" },
            if self.flags & 2 != 0 { "W" } else { "-" },
            if self.flags & 1 != 0 { "X" } else { "-" }
        )
    }
    pub fn kind_name(&self) -> String {
        match self.kind {
            0 => "NULL",
            1 => "LOAD",
            2 => "DYNAMIC",
            3 => "INTERP",
            4 => "NOTE",
            6 => "PHDR",
            7 => "TLS",
            0x6474e550 => "GNU_EH_FRAME",
            0x6474e551 => "GNU_STACK",
            0x6474e552 => "GNU_RELRO",
            _ => return format!("0x{:x}", self.kind),
        }
        .into()
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Function {
    pub address: u64,
    pub size: u64,
    pub name: String,
    pub source: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct SymbolIndex {
    pub functions: Vec<Function>,
    pub truncated: bool,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Metadata {
    pub path: PathBuf,
    pub file_size: u64,
    pub bits: u8,
    pub little_endian: bool,
    pub machine: u16,
    pub file_type: u16,
    pub entry: u64,
    pub segments: Vec<Segment>,
    pub bytes_read: u64,
}
pub struct ElfImage {
    file: File,
    pub path: PathBuf,
    pub length: u64,
    pub bits: u8,
    pub little: bool,
    pub machine: u16,
    pub file_type: u16,
    pub entry: u64,
    pub segments: Vec<Segment>,
    section_offset: u64,
    section_size: u16,
    section_count: u64,
    bytes_read: AtomicU64,
}
#[derive(Clone)]
pub struct Section {
    pub name: String,
    pub kind: u32,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub entry_size: u64,
    pub address: u64,
    pub flags: u64,
}
fn number(bytes: &[u8], offset: usize, size: usize, little: bool) -> Result<u64> {
    let bytes = bytes
        .get(offset..offset + size)
        .ok_or("truncated ELF structure")?;
    let mut n = 0u64;
    if little {
        for (i, b) in bytes.iter().enumerate() {
            n |= (*b as u64) << (i * 8);
        }
    } else {
        for b in bytes {
            n = (n << 8) | *b as u64;
        }
    }
    Ok(n)
}
impl ElfImage {
    /// 只读取 ELF header 和 program headers。不会读取段内容，也不把整个文件映射进内存。
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        // 缓存以打开的文件会话为身份。Windows 上禁止会话期间写入/替换，避免旧页与新文件混用。
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&path)
        }
        .map_err(|e| e.to_string())?;
        #[cfg(not(windows))]
        let file = File::open(&path).map_err(|e| e.to_string())?;
        let length = file.metadata().map_err(|e| e.to_string())?.len();
        let mut image = Self {
            file,
            path,
            length,
            bits: 64,
            little: true,
            machine: 0,
            file_type: 0,
            entry: 0,
            segments: vec![],
            section_offset: 0,
            section_size: 0,
            section_count: 0,
            bytes_read: AtomicU64::new(0),
        };
        let ident = image.read_file(0, 16)?;
        if &ident[..4] != b"\x7fELF" {
            return Err("not an ELF file (expected 7F 45 4C 46)".into());
        }
        image.bits = match ident[4] {
            1 => 32,
            2 => 64,
            _ => return Err("unsupported ELF class".into()),
        };
        image.little = match ident[5] {
            1 => true,
            2 => false,
            _ => return Err("unsupported ELF byte order".into()),
        };
        if ident[6] != 1 {
            return Err("unsupported ELF identification version".into());
        }
        let wide = image.bits == 64;
        let h = image.read_file(0, if wide { 64 } else { 52 })?;
        let n = |o, s| number(&h, o, s, image.little);
        if n(20, 4)? != 1 {
            return Err("unsupported ELF version".into());
        }
        image.file_type = n(16, 2)? as u16;
        image.machine = n(18, 2)? as u16;
        image.entry = n(24, if wide { 8 } else { 4 })?;
        let phoff = n(if wide { 32 } else { 28 }, if wide { 8 } else { 4 })?;
        image.section_offset = n(if wide { 40 } else { 32 }, if wide { 8 } else { 4 })?;
        let phsize = n(if wide { 54 } else { 42 }, 2)?;
        let mut phcount = n(if wide { 56 } else { 44 }, 2)?;
        image.section_size = n(if wide { 58 } else { 46 }, 2)? as u16;
        image.section_count = n(if wide { 60 } else { 48 }, 2)?;
        // ELF extended numbering 只需要 section 0，不遍历 section 内容。
        if phcount == 0xffff || (image.section_count == 0 && image.section_offset != 0) {
            if image.section_size < if wide { 64 } else { 40 } {
                return Err("invalid extended section header".into());
            }
            let s = image.read_file(image.section_offset, if wide { 64 } else { 40 })?;
            if phcount == 0xffff {
                phcount = number(&s, if wide { 44 } else { 28 }, 4, image.little)?;
            }
            if image.section_count == 0 {
                image.section_count = number(
                    &s,
                    if wide { 32 } else { 20 },
                    if wide { 8 } else { 4 },
                    image.little,
                )?;
            }
        }
        if phcount > 0 && phsize < if wide { 56 } else { 32 } {
            return Err("program header entry too short".into());
        }
        let size = phcount
            .checked_mul(phsize)
            .ok_or("program header size overflow")?;
        if size > MAX_TABLE_BYTES || phcount > 65536 {
            return Err("program header resource limit exceeded".into());
        }
        image.bounds(phoff, size)?;
        for i in 0..phcount {
            let b = image.read_file(phoff + i * phsize, if wide { 56 } else { 32 })?;
            let n = |o, s| number(&b, o, s, image.little);
            let seg = if wide {
                Segment {
                    index: i as u32,
                    kind: n(0, 4)? as u32,
                    flags: n(4, 4)? as u32,
                    offset: n(8, 8)?,
                    address: n(16, 8)?,
                    file_size: n(32, 8)?,
                    memory_size: n(40, 8)?,
                    alignment: n(48, 8)?,
                }
            } else {
                Segment {
                    index: i as u32,
                    kind: n(0, 4)? as u32,
                    flags: n(24, 4)? as u32,
                    offset: n(4, 4)?,
                    address: n(8, 4)?,
                    file_size: n(16, 4)?,
                    memory_size: n(20, 4)?,
                    alignment: n(28, 4)?,
                }
            };
            image.bounds(seg.offset, seg.file_size)?;
            seg.address
                .checked_add(seg.memory_size)
                .ok_or("segment virtual range overflow")?;
            if seg.loadable() {
                if seg.file_size > seg.memory_size {
                    return Err("PT_LOAD filesz exceeds memsz".into());
                }
                if seg.alignment > 1
                    && (!seg.alignment.is_power_of_two()
                        || seg.address % seg.alignment != seg.offset % seg.alignment)
                {
                    return Err("invalid PT_LOAD alignment".into());
                }
            }
            image.segments.push(seg);
        }
        Ok(image)
    }
    fn bounds(&self, offset: u64, size: u64) -> Result<()> {
        if offset.checked_add(size).is_none_or(|end| end > self.length) {
            return Err("ELF file range is out of bounds".into());
        }
        Ok(())
    }
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }
    pub fn metadata(&self) -> Metadata {
        Metadata {
            path: self.path.clone(),
            file_size: self.length,
            bits: self.bits,
            little_endian: self.little,
            machine: self.machine,
            file_type: self.file_type,
            entry: self.entry,
            segments: self.segments.clone(),
            bytes_read: self.bytes_read(),
        }
    }
    /// Windows positional I/O：线程之间不共享 seek 光标，不串行锁住文件。
    pub fn read_file(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if size > MAX_READ {
            return Err("single read exceeds 1 MiB budget".into());
        }
        self.bounds(offset, size as u64)?;
        let mut data = vec![0; size];
        let mut done = 0;
        while done < size {
            #[cfg(windows)]
            let count = {
                use std::os::windows::fs::FileExt;
                self.file.seek_read(&mut data[done..], offset + done as u64)
            };
            #[cfg(unix)]
            let count = {
                use std::os::unix::fs::FileExt;
                self.file.read_at(&mut data[done..], offset + done as u64)
            };
            let count = count.map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("file changed or truncated while reading".into());
            }
            done += count;
            self.bytes_read.fetch_add(count as u64, Ordering::Relaxed);
        }
        Ok(data)
    }
    pub fn segment_at(&self, address: u64) -> Option<&Segment> {
        self.segments
            .iter()
            .rev()
            .find(|s| s.loadable() && address >= s.address && address < s.end())
    }
    pub fn executable(&self, address: u64) -> bool {
        self.segment_at(address).is_some_and(Segment::executable)
    }
    pub fn file_offset(&self, address: u64) -> Option<u64> {
        let s = self.segment_at(address)?;
        let d = address - s.address;
        (d < s.file_size).then_some(s.offset + d)
    }
    pub fn initial_address(&self) -> u64 {
        if self.executable(self.entry) {
            self.entry
        } else {
            self.segments
                .iter()
                .find(|s| s.executable())
                .map_or(self.entry, |s| s.address)
        }
    }
    /// BSS 采用虚拟零填充；不为 memsz 提前分配内存。支持跨相邻 LOAD 读取，遇到空洞返回错误。
    pub fn read_virtual(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        if size > MAX_READ {
            return Err("virtual read exceeds 1 MiB budget".into());
        }
        address
            .checked_add(size as u64)
            .ok_or("virtual read overflow")?;
        let mut data = Vec::with_capacity(size);
        let mut at = address;
        while data.len() < size {
            let s = self
                .segment_at(at)
                .ok_or_else(|| format!("unmapped virtual address 0x{at:x}"))?;
            // 后出现的重叠 LOAD 优先，读取必须在覆盖段起点处重新解析映射。
            let end = self
                .segments
                .iter()
                .filter(|next| {
                    next.index > s.index
                        && next.loadable()
                        && next.address > at
                        && next.address < s.end()
                })
                .map(|next| next.address)
                .min()
                .unwrap_or(s.end());
            let count = ((end - at).min((size - data.len()) as u64)) as usize;
            let delta = at - s.address;
            let backed = (s.file_size.saturating_sub(delta).min(count as u64)) as usize;
            if backed > 0 {
                data.extend(self.read_file(s.offset + delta, backed)?);
            }
            data.resize(data.len() + count - backed, 0);
            at += count as u64;
        }
        Ok(data)
    }
    pub fn seed_functions(&self) -> Vec<Function> {
        if self.entry != 0 && self.executable(self.entry) {
            vec![Function {
                address: self.entry,
                size: 0,
                name: "entry_point".into(),
                source: "ELF entry".into(),
            }]
        } else {
            vec![]
        }
    }
    pub fn sections(&self, cancel: &Cancellation) -> Result<Vec<Section>> {
        if self.section_offset == 0 {
            return Ok(vec![]);
        }
        let wide = self.bits == 64;
        if self.section_size < if wide { 64 } else { 40 } {
            return Err("section header too short".into());
        }
        let bytes = self
            .section_count
            .checked_mul(self.section_size as u64)
            .ok_or("section table overflow")?;
        if bytes > MAX_TABLE_BYTES {
            return Err("section table resource limit exceeded".into());
        }
        self.bounds(self.section_offset, bytes)?;
        let mut sections = vec![];
        for i in 0..self.section_count {
            cancel.check()?;
            let b = self.read_file(
                self.section_offset + i * self.section_size as u64,
                if wide { 64 } else { 40 },
            )?;
            let n = |o, s| number(&b, o, s, self.little);
            sections.push(Section {
                name: String::new(),
                kind: n(4, 4)? as u32,
                address: n(if wide { 16 } else { 12 }, if wide { 8 } else { 4 })?,
                flags: n(8, if wide { 8 } else { 4 })?,
                offset: n(if wide { 24 } else { 16 }, if wide { 8 } else { 4 })?,
                size: n(if wide { 32 } else { 20 }, if wide { 8 } else { 4 })?,
                link: n(if wide { 40 } else { 24 }, 4)? as u32,
                entry_size: n(if wide { 56 } else { 36 }, if wide { 8 } else { 4 })?,
            });
        }
        // 名称只用于分类；section 地址映射仍以 LOAD 校验为准。
        let header = self.read_file(0, if wide { 64 } else { 52 })?;
        let mut name_index = number(&header, if wide { 62 } else { 50 }, 2, self.little)? as usize;
        if name_index == 0xffff {
            name_index = sections.first().map_or(0, |s| s.link as usize);
        }
        if let Some(names) = sections.get(name_index).cloned().filter(|s| s.kind == 3) {
            self.bounds(names.offset, names.size)?;
            for (i, section) in sections.iter_mut().enumerate() {
                cancel.check()?;
                let entry =
                    self.read_file(self.section_offset + i as u64 * self.section_size as u64, 4)?;
                let offset = number(&entry, 0, 4, self.little)?;
                if offset < names.size {
                    let text = self.read_file(
                        names.offset + offset,
                        (names.size - offset).min(256) as usize,
                    )?;
                    if let Some(end) = text.iter().position(|b| *b == 0) {
                        section.name = String::from_utf8_lossy(&text[..end]).into_owned();
                    }
                }
            }
        }
        Ok(sections)
    }
    fn string(&self, table: &Section, index: u64) -> Result<String> {
        if index >= table.size {
            return Err("symbol name outside string table".into());
        }
        let data = self.read_file(
            table.offset + index,
            (table.size - index).min(4096) as usize,
        )?;
        let end = data
            .iter()
            .position(|b| *b == 0)
            .ok_or("symbol name exceeds 4096-byte budget")?;
        Ok(String::from_utf8_lossy(&data[..end])
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect())
    }
    /// 显式请求才遍历符号表，按块读取，不触碰代码段。STT_FUNC/GNU_IFUNC 作为有来源的函数种子。
    pub fn symbols(&self, cancel: &Cancellation) -> Result<SymbolIndex> {
        let sections = self.sections(cancel)?;
        let mut result = SymbolIndex {
            functions: self.seed_functions(),
            truncated: false,
            warnings: vec![],
        };
        let mut inspected = 0usize;
        let mut name_bytes = 0usize;
        'tables: for section in sections.iter().filter(|s| s.kind == 2 || s.kind == 11) {
            cancel.check()?;
            let min_size = if self.bits == 64 { 24 } else { 16 };
            if section.entry_size < min_size || section.size % section.entry_size != 0 {
                return Err("invalid symbol table layout".into());
            }
            self.bounds(section.offset, section.size)?;
            let strings = sections
                .get(section.link as usize)
                .ok_or("symbol string table missing")?;
            if strings.kind != 3 {
                return Err("symbol link is not a string table".into());
            }
            self.bounds(strings.offset, strings.size)?;
            let count = section.size / section.entry_size;
            let per_chunk = (65536 / section.entry_size).max(1);
            if section.entry_size > 65536 {
                return Err("symbol entry exceeds budget".into());
            }
            let mut start = 0;
            while start < count {
                cancel.check()?;
                let entries = (count - start)
                    .min(per_chunk)
                    .min(MAX_SYMBOLS.saturating_sub(inspected) as u64);
                if entries == 0 {
                    result.truncated = true;
                    break;
                }
                let bytes = self.read_file(
                    section.offset + start * section.entry_size,
                    (entries * section.entry_size) as usize,
                )?;
                for item in bytes.chunks_exact(section.entry_size as usize) {
                    cancel.check()?;
                    let wide = self.bits == 64;
                    let n = |o, s| number(item, o, s, self.little);
                    let kind = item[if wide { 4 } else { 12 }] & 15;
                    let shndx = n(if wide { 6 } else { 14 }, 2)?;
                    if (kind == 2 || kind == 10) && shndx != 0 {
                        let address = n(if wide { 8 } else { 4 }, if wide { 8 } else { 4 })?;
                        if self.executable(address) {
                            let name = self.string(strings, n(0, 4)?)?;
                            name_bytes += name.len();
                            if name_bytes > 16 * 1024 * 1024 {
                                result.truncated = true;
                                result
                                    .warnings
                                    .push("Function names reached the 16 MiB index budget".into());
                                break 'tables;
                            }
                            result.functions.push(Function {
                                address,
                                size: n(if wide { 16 } else { 8 }, if wide { 8 } else { 4 })?,
                                name: if name.is_empty() {
                                    format!("sub_{address:X}")
                                } else {
                                    name
                                },
                                source: if section.kind == 11 {
                                    ".dynsym"
                                } else {
                                    ".symtab"
                                }
                                .into(),
                            });
                        }
                    }
                }
                inspected += entries as usize;
                start += entries;
            }
            if result.truncated {
                break;
            }
        }
        if sections.is_empty() {
            result.warnings.push("No section table: only ELF entry is indexed. Dynamic-only symbol recovery is not implemented; use address-directed analysis.".into());
        }
        result.functions.sort_by_key(|f| f.address);
        result
            .functions
            .dedup_by(|a, b| a.address == b.address && a.name == b.name);
        Ok(result)
    }
}
