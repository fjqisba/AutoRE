use anyhow::{Result, bail};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use nereus_core::{Architecture, DecodedInstruction};

pub fn decode_one(architecture: Architecture, pc: u64, bytes: &[u8]) -> Result<DecodedInstruction> {
    let mut decoder = Decoder::with_ip(architecture.bitness(), bytes, pc, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        bail!("UNSUPPORTED_INSN: 无效或不完整的指令");
    }
    let mut formatter = IntelFormatter::new();
    let mut text = String::new();
    formatter.format(&instruction, &mut text);
    Ok(DecodedInstruction {
        pc,
        length: instruction.len(),
        text,
        flow: format!("{:?}", instruction.flow_control()),
    })
}
