use crate::semantic_graph::SemanticGraph;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    fmt::Write,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn quoted(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "")
    )
}
fn address(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|value| format!("0x{value:X}")))
        .unwrap_or_else(|| "0x0".into())
}

pub(super) fn to_dot(graph: &SemanticGraph) -> String {
    let mut dot = String::from(
        "digraph VM_Semantics {\n  graph [charset=\"UTF-8\", rankdir=TB, bgcolor=\"#f6f8fc\", pad=0.4, nodesep=0.6, ranksep=0.7, splines=polyline, label=\"NeREUS | 每行一条汇编指令 | 语义身份 (RIP, VIP)\", labelloc=t, fontname=\"Microsoft YaHei\", fontsize=18];\n  node [shape=plain, fontname=\"Consolas\", fontsize=11];\n  edge [fontname=\"Microsoft YaHei\", fontsize=10, arrowsize=0.8, color=\"#425b86\"];\n",
    );
    for (id, node) in &graph.nodes {
        let rip = address(&node["semantic_address"]["rip"]);
        let kind = node["branch"]["kind"].as_str().unwrap_or("not analyzed");
        let status = node["status"].as_str().unwrap_or("discovered");
        let color = match (kind, status) {
            (_, "discovered") => "#68778a",
            ("conditional", _) => "#7651a8",
            ("computed-indirect" | "unresolved", _) => "#a64e21",
            _ => "#234877",
        };
        let _ = write!(
            dot,
            "  {} [id={}, tooltip={}, label=<<TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" CELLPADDING=\"5\" COLOR=\"{color}\">",
            quoted(id),
            quoted(&format!("semantic-{id}")),
            quoted(&format!("Block RIP {rip}, {status}"))
        );
        let _ = write!(
            dot,
            "<TR><TD COLSPAN=\"1\" BGCOLOR=\"{color}\"><FONT COLOR=\"white\"><B>基本块 {}</B></FONT></TD></TR>",
            xml(&rip)
        );
        let _ = write!(
            dot,
            "<TR><TD COLSPAN=\"1\" ALIGN=\"LEFT\" BGCOLOR=\"#e9eff8\">{}</TD></TR>",
            xml(kind)
        );
        if let Some(instructions) = node["instructions"].as_array() {
            for (index, instruction) in instructions.iter().enumerate() {
                let bg = if index + 1 == instructions.len() {
                    "#fff0d1"
                } else if index % 2 == 0 {
                    "#ffffff"
                } else {
                    "#f0f4fa"
                };
                let text = format!(
                    "({}, {})  {}",
                    address(&instruction["rip"]),
                    address(&instruction["vip"]),
                    instruction["assembly"].as_str().unwrap_or("")
                );
                let _ = write!(
                    dot,
                    "<TR><TD ALIGN=\"LEFT\" BGCOLOR=\"{bg}\"><FONT FACE=\"Consolas\">{}</FONT></TD></TR>",
                    xml(&text)
                );
            }
        } else {
            dot.push_str(
                "<TR><TD COLSPAN=\"1\" ALIGN=\"LEFT\">尚未分析 / discovered frontier</TD></TR>",
            );
        }
        if status == "analyzed" && (kind == "computed-indirect" || kind == "unresolved") {
            dot.push_str("<TR><TD COLSPAN=\"1\" BGCOLOR=\"#ffe5d8\" ALIGN=\"LEFT\">未解析边：保留目标表达式，不推测后继</TD></TR>");
        }
        dot.push_str("</TABLE>>];\n");
    }
    for (index, edge) in graph.edges.iter().enumerate() {
        let source = edge["source"].as_str().unwrap_or("");
        let target = edge["target"].as_str().unwrap_or("");
        let kind = edge["kind"].as_str().unwrap_or("unresolved");
        let mut label = kind.to_owned();
        if let Some(condition) = edge["condition"]["condition_smt2"].as_str() {
            // 地址在可见标签里保持十六进制；完整位向量条件置于 tooltip。
            label = format!("{kind}: target = {}", address(&edge["condition"]["target"]));
            let _ = writeln!(
                dot,
                "  {} -> {} [id={}, label={}, tooltip={}, color=\"#7651a8\"] ;",
                quoted(source),
                quoted(target),
                quoted(&format!("edge-{index}")),
                quoted(&label),
                quoted(condition)
            );
        } else {
            let _ = writeln!(
                dot,
                "  {} -> {} [id={}, label={}];",
                quoted(source),
                quoted(target),
                quoted(&format!("edge-{index}")),
                quoted(&label)
            );
        }
    }
    dot.push_str("}\n");
    dot
}

fn dot_program(root: &Path) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("NEREUS_GRAPHVIZ_DOT") {
        return Ok(path.into());
    }
    let local: Value = serde_json::from_slice(&fs::read(root.join("toolchains/local.json"))?)?;
    Ok(local["graphviz_dot"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dot")))
}

pub(super) fn export(root: &Path, directory: &Path, graph: &SemanticGraph) -> Result<Value> {
    let dot_path = directory.join("semantic-graph.dot");
    let svg_path = directory.join("semantic-graph.svg");
    fs::write(&dot_path, to_dot(graph))?;
    // 明确只调用 SVG 后端，不采用截图、位图转换或 PNG 中间产物。
    let mut command = Command::new(dot_program(root)?);
    command.arg("-Tsvg").arg(&dot_path).arg("-o").arg(&svg_path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let result = command
        .output()
        .context("GRAPHVIZ_UNAVAILABLE: 请运行 scripts/build/Install-Graphviz.ps1")?;
    if !result.status.success() {
        bail!(
            "SVG_RENDER_FAILED: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let svg = fs::read_to_string(&svg_path)?;
    if !svg.contains("<svg") || svg.contains("<image") {
        bail!("SVG_INVALID: 要求纯矢量 SVG，禁止嵌入位图");
    }
    let count: usize = graph
        .nodes
        .values()
        .filter_map(|node| node["instructions"].as_array())
        .map(Vec::len)
        .sum();
    let manifest = json!({"formats":["dot","svg"],"raster_used":false,"instruction_rows":count,
        "nodes":graph.nodes.len(),"edges":graph.edges.len(),"dot":dot_path,"svg":svg_path});
    fs::write(
        directory.join("semantic-graph.export.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dot_escapes_labels_and_contains_every_instruction() {
        let graph = SemanticGraph {
            nodes: std::collections::BTreeMap::from([(
                "x".into(),
                json!({
                    "semantic_address":{"rip":"0x401000","vip":"0x500000"},"output_vip":"0x500008","status":"analyzed","branch":{"kind":"direct"},
                    "instructions":[{"rip":"0x401000","vip":"0x500000","bytes":"90","assembly":"a < b & \"x\""},{"rip":"0x401001","bytes":"c3","assembly":"ret"}]
                }),
            )]),
            edges: vec![],
        };
        let dot = to_dot(&graph);
        assert!(dot.contains("a &lt; b &amp; &quot;x&quot;"));
        assert!(dot.contains("0x401001"));
        assert_eq!(dot.matches("FACE=\"Consolas\"").count(), 2);
        assert!(!dot.contains("BYTES"));
        assert!(dot.contains("(0x401001, 0x0)  ret"));
        assert!(dot.contains("(0x401000, 0x500000)  a"));
        assert!(!dot.contains("VIP out:"));
        assert!(!dot.contains("PNG"));
    }
}
