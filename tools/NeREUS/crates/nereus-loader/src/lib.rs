use anyhow::{Context, Result, bail};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Serialize)]
pub struct PeImage {
    pub image_base: u64,
    pub machine: u16,
    pub bitness: u32,
    pub image_size: u32,
    pub sections: Vec<PeSection>,
}

#[derive(Debug, Serialize)]
pub struct MappedAddress {
    pub va: u64,
    pub rva: u32,
    pub file_offset: usize,
    pub section: String,
    pub available_raw_bytes: usize,
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(offset..offset.checked_add(N).context("PE 字段偏移溢出")?)
        .context("PE 头或节区字段被截断")?
        .try_into()
        .context("PE 字段长度不符")
}

impl PeImage {
    /// 读取首选基址下的只读磁盘快照。它是显式快照前提，不声称证明运行时从未改写。
    pub fn readonly_snapshot(&self, bytes: &[u8], va: u64, width: usize) -> Result<Vec<u8>> {
        let rva = va
            .checked_sub(self.image_base)
            .context("快照 VA 小于 ImageBase")?;
        let end = rva.checked_add(width as u64).context("快照区间溢出")?;
        let matches: Vec<_> = self
            .sections
            .iter()
            .filter(|section| {
                rva >= u64::from(section.virtual_address)
                    && end <= u64::from(section.virtual_address) + u64::from(section.raw_size)
            })
            .collect();
        if matches.len() != 1 || matches[0].characteristics & 0x80000000 != 0 {
            bail!("读取不在唯一只读原始区域");
        }
        let section = matches[0];
        let offset =
            section.raw_pointer as usize + (rva - u64::from(section.virtual_address)) as usize;
        Ok(bytes
            .get(offset..offset.checked_add(width).context("文件区间溢出")?)
            .context("快照数据被截断")?
            .to_vec())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.get(..2) != Some(b"MZ") {
            bail!("不是 MZ/PE 文件");
        }
        let nt = u32::from_le_bytes(field(bytes, 0x3c)?) as usize;
        if bytes.get(nt..nt.checked_add(4).context("PE 偏移溢出")?) != Some(b"PE\0\0") {
            bail!("缺少 PE 签名");
        }
        let coff = nt.checked_add(4).context("COFF 偏移溢出")?;
        let machine = u16::from_le_bytes(field(bytes, coff)?);
        let count = u16::from_le_bytes(field(bytes, coff + 2)?) as usize;
        let optional_size = u16::from_le_bytes(field(bytes, coff + 16)?) as usize;
        let optional = coff + 20;
        if optional_size < 64 {
            bail!("Optional Header 过短");
        }
        let magic = u16::from_le_bytes(field(bytes, optional)?);
        let (image_base, bitness) = match (machine, magic) {
            (0x8664, 0x20b) => (u64::from_le_bytes(field(bytes, optional + 24)?), 64),
            (0x14c, 0x10b) => (
                u64::from(u32::from_le_bytes(field(bytes, optional + 28)?)),
                32,
            ),
            _ => bail!("不支持或不一致的 PE machine/magic: {machine:#x}/{magic:#x}"),
        };
        let image_size = u32::from_le_bytes(field(bytes, optional + 56)?);
        let table = optional + optional_size;
        let mut sections = Vec::new();
        for index in 0..count {
            let offset = table + index * 40;
            let name_bytes = field::<8>(bytes, offset)?;
            let name_length = name_bytes.iter().position(|byte| *byte == 0).unwrap_or(8);
            sections.push(PeSection {
                name: String::from_utf8_lossy(&name_bytes[..name_length]).into_owned(),
                virtual_size: u32::from_le_bytes(field(bytes, offset + 8)?),
                virtual_address: u32::from_le_bytes(field(bytes, offset + 12)?),
                raw_size: u32::from_le_bytes(field(bytes, offset + 16)?),
                raw_pointer: u32::from_le_bytes(field(bytes, offset + 20)?),
                characteristics: u32::from_le_bytes(field(bytes, offset + 36)?),
            });
        }
        Ok(Self {
            image_base,
            machine,
            bitness,
            image_size,
            sections,
        })
    }

    pub fn map_executable_va(&self, va: u64, file_length: usize) -> Result<MappedAddress> {
        let rva = u32::try_from(
            va.checked_sub(self.image_base)
                .context("VA 小于 PE 首选 ImageBase")?,
        )?;
        if rva >= self.image_size {
            bail!("地址超出 SizeOfImage");
        }
        let matches: Vec<_> = self
            .sections
            .iter()
            .filter(|section| {
                u64::from(rva) >= u64::from(section.virtual_address)
                    && u64::from(rva)
                        < u64::from(section.virtual_address)
                            + u64::from(section.virtual_size.max(section.raw_size))
            })
            .collect();
        if matches.len() != 1 {
            bail!("地址未命中唯一节区（未映射或重叠）");
        }
        let section = matches[0];
        if section.characteristics & 0x2000_0000 == 0 {
            bail!("目标节区没有执行权限");
        }
        let displacement = rva - section.virtual_address;
        if displacement >= section.raw_size {
            bail!("目标位于没有磁盘字节的虚拟区域，需要快照");
        }
        let file_offset = (section.raw_pointer as usize)
            .checked_add(displacement as usize)
            .context("文件偏移溢出")?;
        let available = (section.raw_size - displacement) as usize;
        if file_offset.checked_add(available).context("节区大小溢出")? > file_length {
            bail!("节区原始数据超出文件");
        }
        Ok(MappedAddress {
            va,
            rva,
            file_offset,
            section: section.name.clone(),
            available_raw_bytes: available,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0xb0..0xb8].copy_from_slice(&0x180000000_u64.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x3000_u32.to_le_bytes());
        let section = 0x188;
        bytes[section..section + 5].copy_from_slice(b".text");
        for (relative, value) in [
            (8, 0x300_u32),
            (12, 0x1000),
            (16, 0x200),
            (20, 0x200),
            (36, 0x60000020),
        ] {
            bytes[section + relative..section + relative + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn pe_mapping_checks_image_base_and_raw_bounds() {
        let bytes = fixture();
        let image = PeImage::parse(&bytes).unwrap();
        assert_eq!(image.image_base, 0x180000000);
        let mapping = image.map_executable_va(0x180001010, bytes.len()).unwrap();
        assert_eq!(mapping.rva, 0x1010);
        assert_eq!(mapping.file_offset, 0x210);
        assert!(image.map_executable_va(0x180001200, bytes.len()).is_err());
        assert!(image.map_executable_va(0x17fffffff, bytes.len()).is_err());
        assert!(
            image
                .map_executable_va(0x180001010, bytes.len() - 1)
                .is_err()
        );
        assert!(PeImage::parse(&bytes[..0x100]).is_err());
    }

    #[test]
    fn snapshot_reads_reject_writable_or_unbacked_regions() {
        let mut bytes = fixture();
        bytes[0x210..0x214].copy_from_slice(&[1, 2, 3, 4]);
        let image = PeImage::parse(&bytes).unwrap();
        assert_eq!(
            image.readonly_snapshot(&bytes, 0x180001010, 4).unwrap(),
            [1, 2, 3, 4]
        );
        assert!(image.readonly_snapshot(&bytes, 0x1800011ff, 4).is_err());
        bytes[0x188 + 36..0x188 + 40].copy_from_slice(&0xe0000020_u32.to_le_bytes());
        assert!(
            PeImage::parse(&bytes)
                .unwrap()
                .readonly_snapshot(&bytes, 0x180001010, 4)
                .is_err()
        );
    }
}
