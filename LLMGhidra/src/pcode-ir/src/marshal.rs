// SPDX-License-Identifier: Apache-2.0
//! Ghidra marshal.hh 的元素/属性协议。Packed 的整数是高位在前的 7-bit 编码，
//! 不是 LEB128；space 使用管理器索引，绝不能序列化 C++ 指针。
use crate::{error, Result, SpaceId, SpaceTable, SpaceType};

pub mod element {
    pub const VOID: u16 = 10;
    pub const ADDR: u16 = 11;
    pub const RANGE: u16 = 12;
    pub const RANGELIST: u16 = 13;
    pub const REGISTER: u16 = 14;
    pub const SEQNUM: u16 = 15;
    pub const VARNODE: u16 = 16;
    pub const OP: u16 = 27;
    pub const SPACEID: u16 = 30;
    pub const BLOCK: u16 = 103;
    pub const BLOCKEDGE: u16 = 104;
    pub const EDGE: u16 = 105;
    pub const IOP: u16 = 113;
    pub const UNIMPL: u16 = 114;
    pub const AST: u16 = 115;
    pub const VARNODES: u16 = 119;
}
pub mod attribute {
    pub const INDEX: u16 = 10;
    pub const NAME: u16 = 14;
    pub const OFFSET: u16 = 16;
    pub const REF: u16 = 18;
    pub const SIZE: u16 = 19;
    pub const SPACE: u16 = 20;
    pub const VALUE: u16 = 25;
    pub const FIRST: u16 = 27;
    pub const LAST: u16 = 28;
    pub const UNIQ: u16 = 29;
    pub const ADDRTIED: u16 = 30;
    pub const GRP: u16 = 31;
    pub const INPUT: u16 = 32;
    pub const PERSISTS: u16 = 33;
    pub const UNAFF: u16 = 34;
    pub const VOLATILE: u16 = 65;
    pub const CODE: u16 = 43;
    pub const END: u16 = 77;
    pub const REV: u16 = 79;
    pub const LOGICALSIZE: u16 = 92;
    pub const PIECE: u16 = 94;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Space(SpaceId),
    Text(String),
}
impl Value {
    pub fn unsigned(&self) -> Result<u64> {
        match self {
            Self::Unsigned(n) => Ok(*n),
            Self::Signed(n) if *n >= 0 => Ok(*n as u64),
            Self::Text(s) => parse_unsigned(s),
            _ => Err(error("expected unsigned integer")),
        }
    }
    pub fn signed(&self) -> Result<i64> {
        match self {
            Self::Signed(n) => Ok(*n),
            Self::Unsigned(n) => i64::try_from(*n).map_err(|_| error("signed integer overflow")),
            Self::Text(s) => parse_signed(s),
            _ => Err(error("expected signed integer")),
        }
    }
    pub fn boolean(&self) -> Result<bool> {
        match self {
            Self::Bool(b) => Ok(*b),
            Self::Text(s) if s == "true" || s == "1" => Ok(true),
            Self::Text(s) if s == "false" || s == "0" => Ok(false),
            _ => Err(error("expected boolean")),
        }
    }
    pub fn space(&self, spaces: &SpaceTable) -> Result<SpaceId> {
        match self {
            Self::Space(s) => Ok(spaces.get(*s)?.id),
            Self::Text(s) => Ok(spaces.named(s)?.id),
            _ => Err(error("expected address space")),
        }
    }
    pub fn text(&self) -> Result<&str> {
        if let Self::Text(s) = self {
            Ok(s)
        } else {
            Err(error("expected string"))
        }
    }
}
pub fn parse_unsigned(text: &str) -> Result<u64> {
    let text = text.trim();
    let (digits, radix) =
        if let Some(s) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (s, 16)
        } else if text.len() > 1 && text.starts_with('0') {
            (&text[1..], 8)
        } else {
            (text, 10)
        };
    u64::from_str_radix(digits, radix).map_err(|_| error(format!("invalid integer {text}")))
}
pub fn parse_signed(text: &str) -> Result<i64> {
    let text = text.trim();
    if let Some(s) = text.strip_prefix('-') {
        let value = parse_unsigned(s)? as i128;
        i64::try_from(-value).map_err(|_| error("signed integer overflow"))
    } else {
        i64::try_from(parse_unsigned(text)?).map_err(|_| error("signed integer overflow"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    pub id: u16,
    pub attributes: Vec<(u16, Value)>,
    pub children: Vec<Element>,
}
impl Element {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            attributes: vec![],
            children: vec![],
        }
    }
    pub fn with(mut self, id: u16, value: Value) -> Self {
        self.attributes.push((id, value));
        self
    }
    pub fn get(&self, id: u16) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|(key, _)| *key == id)
            .map(|(_, v)| v)
    }
    pub fn require(&self, id: u16) -> Result<&Value> {
        self.get(id)
            .ok_or_else(|| error(format!("element {} missing attribute {id}", self.id)))
    }
    pub fn expect(&self, id: u16) -> Result<()> {
        if self.id == id {
            Ok(())
        } else {
            Err(error(format!("expected element {id}, found {}", self.id)))
        }
    }
}

/// 编解码都限制嵌套深度；恶意输入不能造成递归栈耗尽或按不可信长度分配内存。
pub const MAX_DEPTH: usize = 128;
fn header(out: &mut Vec<u8>, kind: u8, id: u16) -> Result<()> {
    if id == 0 || id > 4095 {
        return Err(error("packed identifier outside 1..4095"));
    }
    if id < 32 {
        out.push(kind | id as u8);
    } else {
        out.push(kind | 0x20 | (id >> 7) as u8);
        out.push(0x80 | (id & 127) as u8);
    }
    Ok(())
}
fn integer(out: &mut Vec<u8>, kind: u8, value: u64) {
    let len = (64 - value.leading_zeros()).div_ceil(7) as u8;
    out.push((kind << 4) | len);
    for i in (0..len).rev() {
        out.push(0x80 | ((value >> (i * 7)) & 127) as u8);
    }
}
pub fn encode_packed(root: &Element, spaces: &SpaceTable) -> Result<Vec<u8>> {
    fn emit(node: &Element, spaces: &SpaceTable, out: &mut Vec<u8>, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(error("packed nesting limit"));
        }
        header(out, 0x40, node.id)?;
        let mut seen = std::collections::BTreeSet::new();
        for (id, value) in &node.attributes {
            if !seen.insert(id) {
                return Err(error("duplicate attribute"));
            }
            header(out, 0xc0, *id)?;
            match value {
                Value::Bool(b) => out.push(0x10 | u8::from(*b)),
                Value::Signed(n) => integer(out, if *n < 0 { 3 } else { 2 }, n.unsigned_abs()),
                Value::Unsigned(n) => integer(out, 4, *n),
                Value::Text(s) => {
                    integer(out, 7, s.len() as u64);
                    out.extend_from_slice(s.as_bytes());
                }
                Value::Space(id) => {
                    let sp = spaces.get(*id)?;
                    match sp.kind {
                        SpaceType::Fspec => out.push(0x62),
                        SpaceType::Iop => out.push(0x63),
                        SpaceType::Join => out.push(0x61),
                        SpaceType::Spacebase => {
                            out.push(if sp.flags & 0x20 != 0 { 0x60 } else { 0x64 })
                        }
                        _ => integer(out, 5, id.0 as u64),
                    }
                }
            }
        }
        for child in &node.children {
            emit(child, spaces, out, depth + 1)?;
        }
        header(out, 0x80, node.id)
    }
    let mut bytes = vec![];
    emit(root, spaces, &mut bytes, 0)?;
    Ok(bytes)
}

pub fn decode_packed(bytes: &[u8], spaces: &SpaceTable) -> Result<Element> {
    struct Reader<'a> {
        bytes: &'a [u8],
        pos: usize,
        spaces: &'a SpaceTable,
    }
    impl Reader<'_> {
        fn byte(&mut self) -> Result<u8> {
            let b = *self
                .bytes
                .get(self.pos)
                .ok_or_else(|| error("truncated packed stream"))?;
            self.pos += 1;
            Ok(b)
        }
        fn header(&mut self) -> Result<(u8, u16)> {
            let b = self.byte()?;
            let mut id = (b & 31) as u16;
            if b & 32 != 0 {
                let ext = self.byte()?;
                if ext & 128 == 0 {
                    return Err(error("invalid identifier extension"));
                }
                id = (id << 7) | (ext & 127) as u16;
            }
            if id == 0 || b & 0xc0 == 0 {
                return Err(error("invalid packed header"));
            }
            Ok((b & 0xc0, id))
        }
        fn integer(&mut self, len: u8) -> Result<u64> {
            if len > 10 {
                return Err(error("packed integer longer than uint64"));
            }
            let mut n: u64 = 0;
            for _ in 0..len {
                let b = self.byte()?;
                if b & 128 == 0 || n > u64::MAX >> 7 {
                    return Err(error("invalid packed integer"));
                }
                n = (n << 7) | (b & 127) as u64;
            }
            Ok(n)
        }
        fn value(&mut self) -> Result<Value> {
            let b = self.byte()?;
            let kind = b >> 4;
            let len = b & 15;
            if kind == 1 {
                return match len {
                    0 => Ok(Value::Bool(false)),
                    1 => Ok(Value::Bool(true)),
                    _ => Err(error("invalid packed boolean")),
                };
            }
            if kind == 6 {
                let matches: Vec<_> = self
                    .spaces
                    .iter()
                    .filter(|s| match len {
                        0 => s.kind == SpaceType::Spacebase && s.flags & 0x20 != 0,
                        1 => s.kind == SpaceType::Join,
                        2 => s.kind == SpaceType::Fspec,
                        3 => s.kind == SpaceType::Iop,
                        4 => s.kind == SpaceType::Spacebase && s.flags & 0x20 == 0,
                        _ => false,
                    })
                    .collect();
                return if matches.len() == 1 {
                    Ok(Value::Space(matches[0].id))
                } else {
                    Err(error("unknown or ambiguous special space"))
                };
            }
            let n = self.integer(len)?;
            match kind {
                2 => Ok(Value::Signed(
                    i64::try_from(n).map_err(|_| error("signed overflow"))?,
                )),
                3 => Ok(Value::Signed(
                    i64::try_from(-(n as i128)).map_err(|_| error("negative overflow"))?,
                )),
                4 => Ok(Value::Unsigned(n)),
                5 => {
                    let id = SpaceId(u32::try_from(n).map_err(|_| error("space index overflow"))?);
                    self.spaces.get(id)?;
                    Ok(Value::Space(id))
                }
                7 => {
                    let len = usize::try_from(n).map_err(|_| error("string length overflow"))?;
                    let end = self
                        .pos
                        .checked_add(len)
                        .ok_or_else(|| error("string length overflow"))?;
                    let s = self
                        .bytes
                        .get(self.pos..end)
                        .ok_or_else(|| error("truncated packed string"))?;
                    let s = std::str::from_utf8(s)
                        .map_err(|_| error("invalid UTF-8"))?
                        .to_owned();
                    self.pos = end;
                    Ok(Value::Text(s))
                }
                _ => Err(error("unknown packed attribute type")),
            }
        }
        fn node(&mut self, depth: usize) -> Result<Element> {
            if depth > MAX_DEPTH {
                return Err(error("packed nesting limit"));
            }
            let (kind, id) = self.header()?;
            if kind != 0x40 {
                return Err(error("expected element start"));
            }
            let mut node = Element::new(id);
            loop {
                let b = *self
                    .bytes
                    .get(self.pos)
                    .ok_or_else(|| error("unclosed packed element"))?;
                match b & 0xc0 {
                    0x40 => node.children.push(self.node(depth + 1)?),
                    0x80 => {
                        if self.header()?.1 != id {
                            return Err(error("mismatched element end"));
                        }
                        return Ok(node);
                    }
                    0xc0 => {
                        if !node.children.is_empty() {
                            return Err(error("attribute after child"));
                        }
                        let aid = self.header()?.1;
                        if node.get(aid).is_some() {
                            return Err(error("duplicate attribute"));
                        }
                        let value = self.value()?;
                        node.attributes.push((aid, value));
                    }
                    _ => return Err(error("invalid packed record")),
                }
            }
        }
    }
    let mut reader = Reader {
        bytes,
        pos: 0,
        spaces,
    };
    let root = reader.node(0)?;
    if reader.pos != bytes.len() {
        return Err(error("trailing packed data"));
    }
    Ok(root)
}

const ELEMENTS: &[(u16, &str)] = &[
    (10, "void"),
    (11, "addr"),
    (12, "range"),
    (13, "rangelist"),
    (14, "register"),
    (15, "seqnum"),
    (16, "varnode"),
    (27, "op"),
    (30, "spaceid"),
    (103, "block"),
    (104, "blockedge"),
    (105, "edge"),
    (113, "iop"),
    (114, "unimpl"),
    (115, "ast"),
    (119, "varnodes"),
];
const ATTRIBUTES: &[(u16, &str)] = &[
    (10, "index"),
    (14, "name"),
    (16, "offset"),
    (18, "ref"),
    (19, "size"),
    (20, "space"),
    (25, "value"),
    (27, "first"),
    (28, "last"),
    (29, "uniq"),
    (30, "addrtied"),
    (31, "grp"),
    (32, "input"),
    (33, "persists"),
    (34, "unaff"),
    (65, "volatile"),
    (43, "code"),
    (77, "end"),
    (79, "rev"),
    (92, "logicalsize"),
];
fn name(id: u16, table: &[(u16, &str)], attr: bool) -> Result<String> {
    if let Some((_, name)) = table.iter().find(|(i, _)| *i == id) {
        return Ok((*name).into());
    }
    if attr && (94..=157).contains(&id) {
        return Ok(format!("piece{}", id - 93));
    }
    Err(error(format!("unknown XML identifier {id}")))
}
fn ident(name: &str, table: &[(u16, &str)], attr: bool) -> Result<u16> {
    if let Some((id, _)) = table.iter().find(|(_, s)| *s == name) {
        return Ok(*id);
    }
    if attr {
        if let Some(suffix) = name.strip_prefix("piece") {
            if let Ok(n @ 1..=64) = suffix.parse::<u16>() {
                return Ok(93 + n);
            }
        }
    }
    Err(error(format!("unknown IR XML name {name}")))
}
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn unescape(text: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let end = rest
            .find(';')
            .ok_or_else(|| error("unterminated XML entity"))?;
        let entity = &rest[..end];
        let ch = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let (digits, radix) = if let Some(s) = entity.strip_prefix("#x") {
                    (s, 16)
                } else if let Some(s) = entity.strip_prefix('#') {
                    (s, 10)
                } else {
                    return Err(error("unsupported XML entity"));
                };
                char::from_u32(
                    u32::from_str_radix(digits, radix)
                        .map_err(|_| error("invalid XML character"))?,
                )
                .ok_or_else(|| error("invalid XML character"))?
            }
        };
        if !xml_char(ch) {
            return Err(error("invalid XML character"));
        }
        out.push(ch);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
fn xml_char(c: char) -> bool {
    matches!(c as u32, 9 | 10 | 13 | 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff)
}
pub fn encode_xml(root: &Element, spaces: &SpaceTable) -> Result<String> {
    fn emit(node: &Element, spaces: &SpaceTable, out: &mut String, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(error("XML nesting limit"));
        }
        let tag = name(node.id, ELEMENTS, false)?;
        out.push('<');
        out.push_str(&tag);
        let mut seen = std::collections::BTreeSet::new();
        for (id, value) in &node.attributes {
            if !seen.insert(id) {
                return Err(error("duplicate attribute"));
            }
            let value = match value {
                Value::Bool(b) => b.to_string(),
                Value::Signed(n) => n.to_string(),
                Value::Unsigned(n) => format!("0x{n:x}"),
                Value::Space(id) => spaces.get(*id)?.name.clone(),
                Value::Text(s) => s.clone(),
            };
            if !value.chars().all(xml_char) {
                return Err(error("invalid XML character"));
            }
            out.push(' ');
            out.push_str(&name(*id, ATTRIBUTES, true)?);
            out.push_str("=\"");
            out.push_str(&escape(&value));
            out.push('"');
        }
        if node.children.is_empty() {
            out.push_str("/>");
        } else {
            out.push('>');
            for child in &node.children {
                emit(child, spaces, out, depth + 1)?;
            }
            out.push_str("</");
            out.push_str(&tag);
            out.push('>');
        }
        Ok(())
    }
    let mut text = String::new();
    emit(root, spaces, &mut text, 0)?;
    Ok(text)
}

/// 解析 Ghidra IR 使用的无文本 XML 子集；不接受 DTD、外部实体和未知标签。
/// 对未知内容显式报错，避免“成功导入”却悄悄丢失 IR。
pub fn decode_xml(text: &str, spaces: &SpaceTable) -> Result<Element> {
    struct Parser<'a> {
        rest: &'a str,
        spaces: &'a SpaceTable,
    }
    impl Parser<'_> {
        fn take(&mut self, s: &str) -> bool {
            if let Some(rest) = self.rest.strip_prefix(s) {
                self.rest = rest;
                true
            } else {
                false
            }
        }
        fn misc(&mut self) -> Result<()> {
            loop {
                self.rest = self.rest.trim_start();
                let end = if self.take("<!--") {
                    "-->"
                } else if self.take("<?") {
                    "?>"
                } else {
                    return Ok(());
                };
                let i = self
                    .rest
                    .find(end)
                    .ok_or_else(|| error("unterminated XML comment/declaration"))?;
                self.rest = &self.rest[i + end.len()..];
            }
        }
        fn name(&mut self) -> Result<String> {
            let n = self
                .rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                .count();
            if n == 0 {
                return Err(error("expected XML name"));
            }
            let name = self.rest[..n].to_owned();
            self.rest = &self.rest[n..];
            Ok(name)
        }
        fn node(&mut self, depth: usize) -> Result<Element> {
            if depth > MAX_DEPTH {
                return Err(error("XML nesting limit"));
            }
            self.misc()?;
            if !self.take("<") {
                return Err(error("expected XML start"));
            }
            let tag = self.name()?;
            let mut node = Element::new(ident(&tag, ELEMENTS, false)?);
            loop {
                let had_space = self.rest.starts_with(char::is_whitespace);
                self.rest = self.rest.trim_start();
                if self.take("/>") {
                    return Ok(node);
                }
                if self.take(">") {
                    break;
                }
                if !had_space {
                    return Err(error("attributes must be separated by whitespace"));
                }
                let aid = ident(&self.name()?, ATTRIBUTES, true)?;
                self.rest = self.rest.trim_start();
                if !self.take("=") {
                    return Err(error("expected XML equals"));
                }
                self.rest = self.rest.trim_start();
                let quote = if self.take("\"") {
                    '"'
                } else if self.take("'") {
                    '\''
                } else {
                    return Err(error("expected quoted attribute"));
                };
                let end = self
                    .rest
                    .find(quote)
                    .ok_or_else(|| error("unterminated attribute"))?;
                if self.rest[..end].contains('<') {
                    return Err(error("unescaped less-than in attribute"));
                }
                let text = unescape(&self.rest[..end])?;
                self.rest = &self.rest[end + 1..];
                if node.get(aid).is_some() {
                    return Err(error("duplicate attribute"));
                }
                let v = Value::Text(text);
                let value = match aid {
                    attribute::SPACE => Value::Space(v.space(self.spaces)?),
                    attribute::NAME if node.id == element::SPACEID => {
                        Value::Space(v.space(self.spaces)?)
                    }
                    attribute::ADDRTIED
                    | attribute::INPUT
                    | attribute::PERSISTS
                    | attribute::UNAFF
                    | attribute::VOLATILE => Value::Bool(v.boolean()?),
                    attribute::INDEX
                    | attribute::GRP
                    | attribute::CODE
                    | attribute::END
                    | attribute::REV
                    | attribute::SIZE => Value::Signed(v.signed()?),
                    attribute::OFFSET
                    | attribute::REF
                    | attribute::VALUE
                    | attribute::FIRST
                    | attribute::LAST
                    | attribute::UNIQ
                    | attribute::LOGICALSIZE => Value::Unsigned(v.unsigned()?),
                    _ => v,
                };
                node.attributes.push((aid, value));
            }
            loop {
                self.misc()?;
                if self.take("</") {
                    if self.name()? != tag {
                        return Err(error("mismatched XML close tag"));
                    }
                    self.rest = self.rest.trim_start();
                    if !self.take(">") {
                        return Err(error("invalid close tag"));
                    }
                    return Ok(node);
                }
                node.children.push(self.node(depth + 1)?);
            }
        }
    }
    if !text.chars().all(xml_char) {
        return Err(error("invalid XML character"));
    }
    let mut parser = Parser {
        rest: text.strip_prefix('\u{feff}').unwrap_or(text),
        spaces,
    };
    let node = parser.node(0)?;
    parser.misc()?;
    if !parser.rest.is_empty() {
        return Err(error("trailing XML content"));
    }
    Ok(node)
}
