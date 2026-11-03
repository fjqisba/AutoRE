// SPDX-License-Identifier: Apache-2.0
use crate::{error, Result};
use std::{cmp::Ordering, collections::BTreeMap};

/// 一个 SpaceTable 内唯一，对应 AddrSpace::getIndex()，不是 Java 的复合 space ID。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceId(pub u32);
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceType {
    Constant = 0,
    Processor = 1,
    Spacebase = 2,
    Internal = 3,
    Fspec = 4,
    Iop = 5,
    Join = 6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrSpace {
    pub id: SpaceId,
    pub name: String,
    pub kind: SpaceType,
    pub endian: Endian,
    pub address_size: u32,
    pub word_size: u32,
    pub flags: u32,
    pub delay: i32,
    pub deadcode_delay: i32,
    pub physical_space: Option<SpaceId>,
}
impl AddrSpace {
    pub fn new(
        id: u32,
        name: impl Into<String>,
        kind: SpaceType,
        address_size: u32,
        word_size: u32,
        endian: Endian,
    ) -> Result<Self> {
        if address_size == 0 || address_size > 8 || word_size == 0 {
            return Err(error("invalid address/word size"));
        }
        if id > i32::MAX as u32 {
            return Err(error("space index exceeds Ghidra int4"));
        }
        let name = name.into();
        if name.is_empty() {
            return Err(error("empty space name"));
        }
        Ok(Self {
            id: SpaceId(id),
            name,
            kind,
            endian,
            address_size,
            word_size,
            flags: if endian == Endian::Big { 1 } else { 0 },
            delay: 0,
            deadcode_delay: 0,
            physical_space: None,
        })
    }
    pub fn highest(&self) -> u64 {
        let mask = if self.address_size == 8 {
            u64::MAX
        } else {
            (1u64 << (self.address_size * 8)) - 1
        };
        mask.wrapping_mul(self.word_size as u64)
            .wrapping_add(self.word_size as u64 - 1)
    }
    pub fn wrap_offset(&self, offset: u64) -> u64 {
        let highest = self.highest();
        if offset <= highest {
            return offset;
        }
        // 对齐 C++ 的有符号求余（特别是负位移转 uintb 后的结果）。
        let modulus = highest.wrapping_add(1) as i64;
        if modulus == 0 {
            return offset;
        }
        ((offset as i64 as i128).rem_euclid(modulus as i128)) as u64
    }
    pub fn word_to_byte(&self, offset: u64) -> u64 {
        offset.wrapping_mul(self.word_size as u64)
    }
    pub fn byte_to_word(&self, offset: u64) -> u64 {
        offset / self.word_size as u64
    }
    pub fn address(&self, offset: u64) -> Address {
        Address::new(self.id, offset)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRecord {
    /// pieces[0] 是最高有效部分，与机器端序无关。
    pub pieces: Vec<VarnodeData>,
    pub unified: VarnodeData,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpaceTable {
    spaces: BTreeMap<SpaceId, AddrSpace>,
    registers: BTreeMap<String, VarnodeData>,
    joins: BTreeMap<u64, JoinRecord>,
    join_allocate: u64,
}
impl SpaceTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, space: AddrSpace) -> Result<()> {
        if self.spaces.contains_key(&space.id) || self.spaces.values().any(|s| s.name == space.name)
        {
            return Err(error("duplicate address space index or name"));
        }
        // 同一个空间管理器内，const / unique / join 等由调用者按处理器定义装配。
        if let Some(base) = space.physical_space {
            self.get(base)?;
        }
        self.spaces.insert(space.id, space);
        Ok(())
    }
    pub fn get(&self, id: SpaceId) -> Result<&AddrSpace> {
        self.spaces
            .get(&id)
            .ok_or_else(|| error(format!("unknown space {}", id.0)))
    }
    pub fn named(&self, name: &str) -> Result<&AddrSpace> {
        self.spaces
            .values()
            .find(|s| s.name == name)
            .ok_or_else(|| error(format!("unknown space {name}")))
    }
    pub fn iter(&self) -> impl Iterator<Item = &AddrSpace> {
        self.spaces.values()
    }
    pub fn register(&self, name: &str) -> Result<VarnodeData> {
        self.registers
            .get(name)
            .copied()
            .ok_or_else(|| error(format!("unknown register {name}")))
    }
    pub fn add_register(&mut self, name: impl Into<String>, data: VarnodeData) -> Result<()> {
        data.validate(self)?;
        let name = name.into();
        if name.is_empty() || self.registers.contains_key(&name) {
            return Err(error("empty or duplicate register name"));
        }
        self.registers.insert(name, data);
        Ok(())
    }
    pub fn join(&self, offset: u64) -> Result<&JoinRecord> {
        self.joins
            .get(&offset)
            .ok_or_else(|| error("unlinked join address"))
    }
    pub fn find_add_join(
        &mut self,
        pieces: Vec<VarnodeData>,
        logical_size: u32,
    ) -> Result<VarnodeData> {
        if pieces.is_empty() || pieces.len() > 64 || (pieces.len() == 1) == (logical_size == 0) {
            return Err(error(
                "join requires multiple pieces or one piece with logical size",
            ));
        }
        let mut sum = 0u32;
        for piece in &pieces {
            piece.validate(self)?;
            if self.get(piece.space)?.kind == SpaceType::Join {
                return Err(error("recursive join piece"));
            }
            sum = sum
                .checked_add(piece.size)
                .ok_or_else(|| error("join size overflow"))?;
        }
        let size = if logical_size == 0 { sum } else { logical_size };
        if size > i32::MAX as u32 {
            return Err(error("join size exceeds int4"));
        }
        if let Some(record) = self
            .joins
            .values()
            .find(|j| j.pieces == pieces && j.unified.size == size)
        {
            return Ok(record.unified);
        }
        let space = self
            .spaces
            .values()
            .find(|s| s.kind == SpaceType::Join)
            .ok_or_else(|| error("join space missing"))?
            .id;
        let next = self
            .join_allocate
            .checked_add((size as u64 + 15) & !15)
            .ok_or_else(|| error("join space exhausted"))?;
        let unified = VarnodeData::new(space, self.join_allocate, size);
        self.joins
            .insert(self.join_allocate, JoinRecord { pieces, unified });
        self.join_allocate = next;
        Ok(unified)
    }
    pub fn constant(&self) -> Result<&AddrSpace> {
        self.spaces
            .values()
            .find(|s| s.kind == SpaceType::Constant)
            .ok_or_else(|| error("constant space missing"))
    }
    pub fn validate_address(&self, address: Address) -> Result<()> {
        let (space, offset) = address.parts()?;
        if offset > self.get(space)?.highest() {
            return Err(error("address exceeds address space"));
        }
        Ok(())
    }
}

/// C++ 的 null / 最大指针哨兵改为显式枚举，不制造悬空指针。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    #[default]
    Invalid,
    Location {
        space: SpaceId,
        offset: u64,
    },
    Maximum,
}
impl Address {
    pub const fn new(space: SpaceId, offset: u64) -> Self {
        Self::Location { space, offset }
    }
    pub fn parts(self) -> Result<(SpaceId, u64)> {
        match self {
            Self::Location { space, offset } => Ok((space, offset)),
            _ => Err(error("sentinel is not a storage address")),
        }
    }
    pub fn add(self, displacement: i64, spaces: &SpaceTable) -> Result<Self> {
        let (space, offset) = self.parts()?;
        Ok(Self::new(
            space,
            spaces
                .get(space)?
                .wrap_offset(offset.wrapping_add(displacement as u64)),
        ))
    }
    pub fn valid_range(self, size: u64, spaces: &SpaceTable) -> Result<bool> {
        let (space, offset) = self.parts()?;
        Ok(size != 0
            && offset <= spaces.get(space)?.highest()
            && size - 1 <= spaces.get(space)?.highest() - offset)
    }
    pub fn display(self, spaces: &SpaceTable) -> Result<String> {
        match self {
            Self::Invalid => Ok("<invalid>".into()),
            Self::Maximum => Ok("<maximum>".into()),
            Self::Location { space, offset } => {
                Ok(format!("{}:{offset:x}", spaces.get(space)?.name))
            }
        }
    }
}

/// Ghidra 的 SeqNum equality 只比较 time，排序却比较 address+time。
/// 因而不能为它实现 Rust 的 Eq/Ord（会违反容器契约）；分别提供显式操作和排序键。
#[derive(Clone, Copy, Debug)]
pub struct SeqNum {
    pub address: Address,
    pub time: u32,
    pub order: u32,
}
impl SeqNum {
    pub const fn new(address: Address, time: u32) -> Self {
        Self {
            address,
            time,
            order: 0,
        }
    }
    pub const fn same_time(self, other: Self) -> bool {
        self.time == other.time
    }
    pub const fn key(self) -> (Address, u32) {
        (self.address, self.time)
    }
    pub fn compare(self, other: Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VarnodeData {
    pub space: SpaceId,
    pub offset: u64,
    pub size: u32,
}
impl VarnodeData {
    pub const fn new(space: SpaceId, offset: u64, size: u32) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }
    pub const fn address(self) -> Address {
        Address::new(self.space, self.offset)
    }
    pub fn validate(self, spaces: &SpaceTable) -> Result<()> {
        spaces.get(self.space)?;
        if self.size == 0 || self.size > i32::MAX as u32 {
            return Err(error("varnode must have positive int4 byte size"));
        }
        Ok(())
    }
    pub fn contains(self, other: Self) -> bool {
        self.size != 0
            && other.size != 0
            && self.space == other.space
            && other.offset >= self.offset
            && self.offset.wrapping_add(self.size as u64 - 1)
                >= other.offset.wrapping_add(other.size as u64 - 1)
    }
    pub fn is_contiguous(self, low: Self, spaces: &SpaceTable) -> Result<bool> {
        if self.space != low.space {
            return Ok(false);
        }
        let space = spaces.get(self.space)?;
        Ok(match space.endian {
            Endian::Big => {
                space.wrap_offset(self.offset.wrapping_add(self.size as u64)) == low.offset
            }
            Endian::Little => {
                space.wrap_offset(low.offset.wrapping_add(low.size as u64)) == self.offset
            }
        })
    }
}
impl Ord for VarnodeData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.space
            .cmp(&other.space)
            .then(self.offset.cmp(&other.offset))
            .then(other.size.cmp(&self.size))
    }
}
impl PartialOrd for VarnodeData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddressRange {
    pub space: SpaceId,
    pub first: u64,
    pub last: u64,
}
impl AddressRange {
    pub fn new(space: SpaceId, first: u64, last: u64) -> Result<Self> {
        if first > last {
            return Err(error("reversed address range"));
        }
        Ok(Self { space, first, last })
    }
    pub fn contains(self, address: Address) -> bool {
        matches!(address, Address::Location { space, offset } if space == self.space && offset >= self.first && offset <= self.last)
    }
}
