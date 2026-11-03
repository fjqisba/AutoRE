use anyhow::{Result, bail};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};
use nereus_core::{Architecture, BlockInstruction, DecodedBlock, DecodedInstruction};

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

pub fn decode_basic_block(
    architecture: Architecture,
    pc: u64,
    bytes: &[u8],
    max_instructions: usize,
) -> Result<DecodedBlock> {
    let mut decoder = Decoder::with_ip(architecture.bitness(), bytes, pc, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut formatter = IntelFormatter::new();
    while decoder.can_decode() && instructions.len() < max_instructions {
        let start = decoder.position();
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            bail!(
                "UNSUPPORTED_INSN: 无效/截断指令，VA={:#x}",
                instruction.ip()
            );
        }
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        let flow = instruction.flow_control();
        instructions.push(BlockInstruction {
            instruction: DecodedInstruction {
                pc: instruction.ip(),
                length: instruction.len(),
                text,
                flow: format!("{flow:?}"),
            },
            bytes: bytes[start..decoder.position()]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        });
        // 采用 call 也终结块的保守策略，不越过控制转移或异常指令线性反汇编。
        if flow != FlowControl::Next {
            let direct_target = match instruction.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instruction.near_branch_target())
                }
                _ => None,
            };
            let fallthrough = match flow {
                FlowControl::ConditionalBranch | FlowControl::Call | FlowControl::IndirectCall => {
                    Some(instruction.next_ip())
                }
                _ => None,
            };
            return Ok(DecodedBlock {
                start_pc: pc,
                end_pc_exclusive: instruction.next_ip(),
                byte_length: decoder.position(),
                instructions,
                terminator: format!("{flow:?}"),
                direct_target,
                fallthrough,
            });
        }
    }
    bail!("BUDGET_EXCEEDED: 在字节/指令预算内未发现基本块终结指令，不提交截断块")
}
