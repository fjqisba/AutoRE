use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86,
    Amd64,
}

impl Architecture {
    pub fn bitness(self) -> u32 {
        match self {
            Self::X86 => 32,
            Self::Amd64 => 64,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecodedInstruction {
    pub pc: u64,
    pub length: usize,
    pub text: String,
    pub flow: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockInstruction {
    #[serde(flatten)]
    pub instruction: DecodedInstruction,
    pub bytes: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecodedBlock {
    pub start_pc: u64,
    pub end_pc_exclusive: u64,
    pub byte_length: usize,
    pub instructions: Vec<BlockInstruction>,
    pub terminator: String,
    pub direct_target: Option<u64>,
    pub fallthrough: Option<u64>,
}
