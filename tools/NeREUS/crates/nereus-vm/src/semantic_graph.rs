use anyhow::{Context, Result};
use nereus_core::DecodedBlock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod hex_address {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{value:X}"))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
    }
}
mod optional_hex_address {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&format!("0x{value:X}")),
            None => serializer.serialize_str("0x0"),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .filter(|text| text != "0x0")
            .map(|text| {
                u64::from_str_radix(text.trim_start_matches("0x"), 16)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticAddress {
    #[serde(rename = "rip", with = "hex_address")]
    pub eip: u64,
    #[serde(with = "optional_hex_address")]
    pub vip: Option<u64>,
}
impl SemanticAddress {
    pub fn id(&self) -> String {
        format!(
            "{:x}:{}",
            self.eip,
            self.vip
                .map_or_else(|| "0".into(), |vip| format!("{vip:x}"))
        )
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct SemanticGraph {
    pub nodes: BTreeMap<String, Value>,
    pub edges: Vec<Value>,
}
impl SemanticGraph {
    pub fn enter(
        &mut self,
        address: &SemanticAddress,
        output_vip: Option<u64>,
        classification: &Value,
        evidence: &Value,
        block: &DecodedBlock,
        first_ordinal: usize,
    ) {
        if address.vip.is_some() {
            let unknown = SemanticAddress {
                eip: address.eip,
                vip: None,
            }
            .id();
            if self
                .nodes
                .get(&unknown)
                .is_some_and(|node| node["status"] == "discovered")
            {
                self.nodes.remove(&unknown);
                for edge in &mut self.edges {
                    if edge["target"] == unknown {
                        edge["target"] = address.id().into();
                    }
                }
            }
        }
        self.nodes.insert(
            address.id(),
            json!({"semantic_address":address,"status":"analyzed",
            "output_vip":format!("0x{:X}",output_vip.unwrap_or(0)),"branch":classification,"context_evidence":evidence,
            "instructions":block.instructions.iter().enumerate().map(|(index,instruction)|json!({
                "ordinal":first_ordinal+index,"rip":format!("0x{:X}",instruction.instruction.pc),
                "vip":"0x0","vip_initialized":false,"vip_resolved":false,"vip_boundary":"before-native-instruction",
                "bytes":instruction.bytes,
                "assembly":instruction.instruction.text,"flow":instruction.instruction.flow})).collect::<Vec<_>>(),
            "end_rip_exclusive":format!("0x{:X}",block.end_pc_exclusive)}),
        );
    }
    pub fn apply_instruction_vips(&mut self, rows: &[Value], final_vip: Option<u64>) -> Result<()> {
        let mut mapping = BTreeMap::new();
        let mut updated = BTreeMap::new();
        for (old_id, mut node) in std::mem::take(&mut self.nodes) {
            if let Some(instructions) = node["instructions"].as_array_mut() {
                for instruction in instructions.iter_mut() {
                    let ordinal = instruction["ordinal"].as_u64().context("指令序号缺失")? as usize;
                    let row = rows.get(ordinal).context("逐指令 VIP 快照缺失")?;
                    let rip = u64::from_str_radix(
                        instruction["rip"]
                            .as_str()
                            .context("RIP 缺失")?
                            .trim_start_matches("0x"),
                        16,
                    )?;
                    let traced_rip = u64::from_str_radix(
                        row["rip"]
                            .as_str()
                            .context("快照 RIP 缺失")?
                            .trim_start_matches("0x"),
                        16,
                    )?;
                    anyhow::ensure!(rip == traced_rip, "逐指令 VIP 快照和原生 RIP 不一致");
                    let value = hex(&row["vip"]).context("VIP 缺失")?;
                    instruction["vip"] = format!("0x{value:X}").into();
                    instruction["vip_initialized"] = row["vip_initialized"].clone();
                    instruction["vip_resolved"] = row["vip_resolved"].clone();
                    instruction["vip_source"] = row["source"].clone();
                }
                if let (Some(first), Some(last)) = (instructions.first(), instructions.last()) {
                    let first_vip = first["vip"].clone();
                    let after = last["ordinal"].as_u64().context("指令序号缺失")? as usize + 1;
                    let output = rows
                        .get(after)
                        .and_then(|row| hex(&row["vip"]))
                        .or(final_vip)
                        .unwrap_or(0);
                    node["semantic_address"]["vip"] = first_vip;
                    node["output_vip"] = format!("0x{output:X}").into();
                }
                let address: SemanticAddress =
                    serde_json::from_value(node["semantic_address"].clone())?;
                mapping.insert(old_id, address.id());
                updated.insert(address.id(), node);
            } else {
                updated.insert(old_id, node);
            }
        }
        self.nodes = updated;
        for edge in &mut self.edges {
            for endpoint in ["source", "target"] {
                if let Some(next) = edge[endpoint].as_str().and_then(|old| mapping.get(old)) {
                    edge[endpoint] = next.clone().into();
                }
            }
        }
        Ok(())
    }
    pub fn edge(
        &mut self,
        source: &SemanticAddress,
        target: SemanticAddress,
        kind: &str,
        condition: Option<&Value>,
    ) {
        self.nodes
            .entry(target.id())
            .or_insert_with(|| json!({"semantic_address":target,"status":"discovered"}));
        self.edges.push(
            json!({"source":source.id(),"target":target.id(),"kind":kind,"condition":condition}),
        );
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct VipTracker {
    pub stream_base: Option<u64>,
    pub current: Option<u64>,
    pub cursor_slot_from_entry_rsp: Option<i64>,
    pub evidence: Vec<Value>,
}
fn hex(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.trim_start_matches("0x"), 16).ok()
}
impl VipTracker {
    pub fn update(&mut self, initialization: &Value, optimization: &Value) {
        if self.stream_base.is_none()
            && let (Some(roles), Some(reads)) = (
                initialization["register_roles"].as_array(),
                optimization["snapshot_reads"].as_array(),
            )
        {
            let mut candidates = Vec::new();
            for role in roles {
                let Some(address) = hex(&role["constant"]) else {
                    continue;
                };
                if reads
                    .iter()
                    .any(|read| hex(&read["address"]) == Some(address))
                {
                    candidates.push((address, role));
                }
            }
            candidates.sort_by_key(|value| value.0);
            candidates.dedup_by_key(|value| value.0);
            if candidates.len() == 1 {
                self.stream_base = Some(candidates[0].0);
                self.current = self.stream_base;
                self.evidence.push(json!({"kind":"register-held-address-consumed-by-guest-read","address":self.stream_base,
                        "register_at_observation":candidates[0].1["register"],"scope":"current-VM-entry-dataflow-candidate"}));
            }
        }
        let (Some(seed), Some(writes)) = (
            self.stream_base,
            initialization["runtime_context_writes"].as_array(),
        ) else {
            return;
        };
        for write in writes {
            let (Some(address), Some(slot)) =
                (hex(&write["constant"]), write["entry_rsp_offset"].as_i64())
            else {
                continue;
            };
            if self.cursor_slot_from_entry_rsp == Some(slot)
                || (self.cursor_slot_from_entry_rsp.is_none()
                    && address >= seed
                    && address - seed < 4096)
            {
                self.cursor_slot_from_entry_rsp = Some(slot);
                self.current = Some(address);
                self.evidence.push(json!({"kind":"runtime-context-cursor-write","entry_rsp_offset":slot,"value":address}));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handler_with_different_vip_is_a_different_semantic_node() {
        let first = SemanticAddress {
            eip: 0x401000,
            vip: Some(0x500000),
        };
        let second = SemanticAddress {
            eip: 0x401000,
            vip: Some(0x500008),
        };
        assert_ne!(first, second);
        assert_ne!(first.id(), second.id());
        let mut graph = SemanticGraph::default();
        let block = DecodedBlock {
            start_pc: first.eip,
            end_pc_exclusive: first.eip + 1,
            byte_length: 1,
            instructions: vec![],
            terminator: "Return".into(),
            direct_target: None,
            fallthrough: None,
        };
        graph.enter(&first, second.vip, &json!({}), &json!({}), &block, 0);
        graph.edge(&first, second.clone(), "direct", None);
        assert_eq!(graph.nodes.len(), 2);
        graph.enter(&second, None, &json!({}), &json!({}), &block, 0);
        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn per_instruction_vip_is_not_filled_from_block_header() {
        use nereus_core::{BlockInstruction, DecodedInstruction};
        let address = SemanticAddress {
            eip: 0x401000,
            vip: Some(0x500000),
        };
        let instructions = (0..2)
            .map(|index| BlockInstruction {
                instruction: DecodedInstruction {
                    pc: 0x401000 + index,
                    length: 1,
                    text: "nop".into(),
                    flow: "Next".into(),
                },
                bytes: "90".into(),
            })
            .collect();
        let block = DecodedBlock {
            start_pc: 0x401000,
            end_pc_exclusive: 0x401002,
            byte_length: 2,
            instructions,
            terminator: "Next".into(),
            direct_target: None,
            fallthrough: None,
        };
        let mut graph = SemanticGraph::default();
        graph.enter(&address, Some(0x500008), &json!({}), &json!({}), &block, 0);
        graph.apply_instruction_vips(&[
            json!({"rip":"0x401000","vip":"0x0","vip_initialized":false,"vip_resolved":false,"source":"not-initialized"}),
            json!({"rip":"0x401001","vip":"0x500008","vip_initialized":true,"vip_resolved":true,"source":"cursor-memory-version"})
        ],Some(0x500008)).unwrap();
        let node = &graph.nodes["401000:0"];
        assert_eq!(node["instructions"][0]["vip"], "0x0");
        assert_eq!(node["instructions"][1]["vip"], "0x500008");
        assert_eq!(node["semantic_address"]["vip"], "0x0");
    }
}
