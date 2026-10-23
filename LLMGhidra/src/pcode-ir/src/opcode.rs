// SPDX-License-Identifier: Apache-2.0
use crate::{error, Result};
use std::{fmt, str::FromStr};

macro_rules! opcodes {
    ($($name:ident = $value:literal),+ $(,)?) => {
        /// 与 opcodes.hh / PcodeOp.java 相同的数字。45 是空槽，75 是上界而非指令。
        #[allow(non_camel_case_types)]
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum OpCode { $($name = $value),+ }
        impl OpCode {
            pub const MAX: u32 = 75;
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
            pub const fn mnemonic(self) -> &'static str { match self { $(Self::$name => stringify!($name)),+ } }
            pub const fn number(self) -> u32 { self as u32 }
        }
        impl TryFrom<u32> for OpCode {
            type Error = crate::Error;
            fn try_from(value: u32) -> Result<Self> {
                match value { $($value => Ok(Self::$name),)+ _ => Err(error(format!("invalid P-code opcode {value}"))) }
            }
        }
    }
}
opcodes! {
    UNIMPLEMENTED = 0, COPY = 1, LOAD = 2, STORE = 3,
    BRANCH = 4, CBRANCH = 5, BRANCHIND = 6, CALL = 7, CALLIND = 8, CALLOTHER = 9, RETURN = 10,
    INT_EQUAL = 11, INT_NOTEQUAL = 12, INT_SLESS = 13, INT_SLESSEQUAL = 14, INT_LESS = 15, INT_LESSEQUAL = 16,
    INT_ZEXT = 17, INT_SEXT = 18, INT_ADD = 19, INT_SUB = 20, INT_CARRY = 21, INT_SCARRY = 22, INT_SBORROW = 23,
    INT_2COMP = 24, INT_NEGATE = 25, INT_XOR = 26, INT_AND = 27, INT_OR = 28, INT_LEFT = 29, INT_RIGHT = 30,
    INT_SRIGHT = 31, INT_MULT = 32, INT_DIV = 33, INT_SDIV = 34, INT_REM = 35, INT_SREM = 36,
    BOOL_NEGATE = 37, BOOL_XOR = 38, BOOL_AND = 39, BOOL_OR = 40,
    FLOAT_EQUAL = 41, FLOAT_NOTEQUAL = 42, FLOAT_LESS = 43, FLOAT_LESSEQUAL = 44,
    FLOAT_NAN = 46, FLOAT_ADD = 47, FLOAT_DIV = 48, FLOAT_MULT = 49, FLOAT_SUB = 50, FLOAT_NEG = 51,
    FLOAT_ABS = 52, FLOAT_SQRT = 53, FLOAT_INT2FLOAT = 54, FLOAT_FLOAT2FLOAT = 55, FLOAT_TRUNC = 56,
    FLOAT_CEIL = 57, FLOAT_FLOOR = 58, FLOAT_ROUND = 59,
    MULTIEQUAL = 60, INDIRECT = 61, PIECE = 62, SUBPIECE = 63, CAST = 64, PTRADD = 65, PTRSUB = 66,
    SEGMENTOP = 67, CPOOLREF = 68, NEW = 69, INSERT = 70, ZPULL = 71, POPCOUNT = 72, LZCOUNT = 73, SPULL = 74
}
impl FromStr for OpCode {
    type Err = crate::Error;
    fn from_str(name: &str) -> Result<Self> {
        // 不强制大写：Ghidra 名称查找大小写敏感。
        if let Some(op) = Self::ALL.iter().find(|op| op.mnemonic() == name) {
            return Ok(*op);
        }
        match name {
            "BUILD" => Ok(Self::MULTIEQUAL),
            "DELAY_SLOT" => Ok(Self::INDIRECT),
            "LABEL" => Ok(Self::PTRADD),
            "CROSSBUILD" => Ok(Self::PTRSUB),
            "INT2FLOAT" => Ok(Self::FLOAT_INT2FLOAT),
            "FLOAT2FLOAT" => Ok(Self::FLOAT_FLOAT2FLOAT),
            "TRUNC" => Ok(Self::FLOAT_TRUNC),
            "CEIL" => Ok(Self::FLOAT_CEIL),
            "FLOOR" => Ok(Self::FLOAT_FLOOR),
            "ROUND" => Ok(Self::FLOAT_ROUND),
            "EXTRACT" => Ok(Self::ZPULL),
            _ => Err(error(format!("unknown P-code mnemonic {name}"))),
        }
    }
}
impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}
impl OpCode {
    /// TypeOp 设置的位必须随 opcode 一起更换，其余分析标志不受影响。
    pub const TYPE_FLAGS: u32 = 0x20000000
        | 0x80000
        | 0x40000
        | 0x20000
        | 0x10000
        | 0x8000
        | 0x4000
        | 0x800
        | 0x80
        | 0x40
        | 0x10
        | 0x8
        | 0x4
        | 0x2;
    pub fn default_flags(self) -> crate::flags::OpFlags {
        use crate::flags::OpFlags as F;
        use OpCode::*;
        match self {
            UNIMPLEMENTED => F(0),
            COPY => F::unary | F::nocollapse,
            LOAD | STORE | SEGMENTOP | CPOOLREF => F::special | F::nocollapse,
            BRANCH | CBRANCH => F::special | F::branch | F::coderef | F::nocollapse,
            BRANCHIND => F::special | F::branch | F::nocollapse,
            CALL => F::special | F::call | F::has_callspec | F::coderef | F::nocollapse,
            CALLIND => F::special | F::call | F::has_callspec | F::nocollapse,
            CALLOTHER | NEW => F::special | F::call | F::nocollapse,
            RETURN => F::special | F::returns | F::nocollapse | F::return_copy,
            INT_EQUAL | INT_NOTEQUAL | INT_CARRY | INT_SCARRY | BOOL_XOR | BOOL_AND | BOOL_OR
            | FLOAT_EQUAL | FLOAT_NOTEQUAL => F::binary | F::booloutput | F::commutative,
            INT_SLESS | INT_SLESSEQUAL | INT_LESS | INT_LESSEQUAL | INT_SBORROW | FLOAT_LESS
            | FLOAT_LESSEQUAL => F::binary | F::booloutput,
            BOOL_NEGATE | FLOAT_NAN => F::unary | F::booloutput,
            INT_ADD | INT_MULT | INT_XOR | INT_AND | INT_OR | FLOAT_ADD | FLOAT_MULT => {
                F::binary | F::commutative
            }
            MULTIEQUAL | INDIRECT => F::special | F::marker | F::nocollapse,
            CAST => F::unary | F::special | F::nocollapse,
            PTRADD => F::ternary | F::nocollapse,
            PTRSUB => F::binary | F::nocollapse,
            INSERT | ZPULL | SPULL => F::ternary,
            INT_ZEXT | INT_SEXT | INT_2COMP | INT_NEGATE | FLOAT_NEG | FLOAT_ABS | FLOAT_SQRT
            | FLOAT_INT2FLOAT | FLOAT_FLOAT2FLOAT | FLOAT_TRUNC | FLOAT_CEIL | FLOAT_FLOOR
            | FLOAT_ROUND | POPCOUNT | LZCOUNT => F::unary,
            INT_SUB | INT_LEFT | INT_RIGHT | INT_SRIGHT | INT_DIV | INT_SDIV | INT_REM
            | INT_SREM | FLOAT_DIV | FLOAT_SUB | PIECE | SUBPIECE => F::binary,
        }
    }
    /// 本地旧 opcodes.cc 的模板名称；SPULL 在旧表中缺项，不能越界伪造返回值。
    pub fn native_name(self) -> Option<&'static str> {
        Some(match self {
            Self::UNIMPLEMENTED => "BLANK",
            Self::MULTIEQUAL => "BUILD",
            Self::INDIRECT => "DELAY_SLOT",
            Self::PTRADD => "LABEL",
            Self::PTRSUB => "CROSSBUILD",
            Self::FLOAT_INT2FLOAT => "INT2FLOAT",
            Self::FLOAT_FLOAT2FLOAT => "FLOAT2FLOAT",
            Self::FLOAT_TRUNC => "TRUNC",
            Self::FLOAT_CEIL => "CEIL",
            Self::FLOAT_FLOOR => "FLOOR",
            Self::FLOAT_ROUND => "ROUND",
            Self::ZPULL => "EXTRACT",
            Self::SPULL => return None,
            op => op.mnemonic(),
        })
    }
    /// 对齐 get_booleanflip；bool 表示是否交换两个输入。
    pub const fn boolean_flip(self) -> Option<(Self, bool)> {
        use OpCode::*;
        Some(match self {
            INT_EQUAL => (INT_NOTEQUAL, false),
            INT_NOTEQUAL => (INT_EQUAL, false),
            INT_SLESS => (INT_SLESSEQUAL, true),
            INT_SLESSEQUAL => (INT_SLESS, true),
            INT_LESS => (INT_LESSEQUAL, true),
            INT_LESSEQUAL => (INT_LESS, true),
            BOOL_NEGATE => (COPY, false),
            FLOAT_EQUAL => (FLOAT_NOTEQUAL, false),
            FLOAT_NOTEQUAL => (FLOAT_EQUAL, false),
            FLOAT_LESS => (FLOAT_LESSEQUAL, true),
            FLOAT_LESSEQUAL => (FLOAT_LESS, true),
            _ => return None,
        })
    }
    pub const fn is_call(self) -> bool {
        matches!(self, Self::CALL | Self::CALLIND | Self::CALLOTHER)
    }
    pub const fn is_branch(self) -> bool {
        matches!(self, Self::BRANCH | Self::CBRANCH | Self::BRANCHIND)
    }
    pub const fn is_marker(self) -> bool {
        matches!(self, Self::MULTIEQUAL | Self::INDIRECT)
    }
}
