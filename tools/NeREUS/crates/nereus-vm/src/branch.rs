use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn solve(root: &Path, text: &str) -> Result<String> {
    let config: Value = serde_json::from_slice(&fs::read(root.join("toolchains/local.json"))?)?;
    let program = config["z3"].as_str().context("Z3 未配置")?;
    let mut command = Command::new(program);
    command
        .args(["-in", "-T:2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .context("Z3 stdin 缺失")?
        .write_all(text.as_bytes())?;
    let output = child.wait_with_output()?;
    Ok(String::from_utf8(output.stdout)?)
}

fn value(text: &str) -> Result<u64> {
    for token in text.split_whitespace() {
        let token = token.trim_matches(|ch| ch == '(' || ch == ')');
        if let Some(hex) = token.strip_prefix("#x") {
            return Ok(u64::from_str_radix(hex, 16)?);
        }
        if let Some(binary) = token.strip_prefix("#b") {
            return Ok(u64::from_str_radix(binary, 2)?);
        }
        if let Some(decimal) = token.strip_prefix("bv")
            && decimal.chars().all(|ch| ch.is_ascii_digit())
        {
            return Ok(decimal.parse()?);
        }
    }
    bail!("无法解析 Z3 目标值：{text}")
}

pub(super) fn classify(root: &Path, directory: &Path, analysis: &Value) -> Result<Value> {
    if analysis["kind"] == "direct" {
        return Ok(
            json!({"kind":"direct","targets":[analysis["target"]],"target_set_complete":true,"evidence":"constant-SSA-target"}),
        );
    }
    let Some(smt) = analysis["smt2"].as_str() else {
        return Ok(json!({"kind":"unresolved","reason":analysis["reason"]}));
    };
    fs::write(directory.join("branch.target.smt2"), smt)?;
    let width = analysis["target_width"].as_u64().context("目标位宽缺失")?;
    let mut targets = Vec::new();
    let mut constraints = String::new();
    let mut queries = Vec::new();
    let mut complete = false;
    for index in 0..3 {
        let query = format!("{smt}{constraints}(check-sat)\n");
        let status = solve(root, &query)?;
        fs::write(directory.join(format!("branch.query-{index}.smt2")), &query)?;
        queries.push(json!({"index":index,"status":status.trim()}));
        if status.lines().next() == Some("unsat") {
            complete = true;
            break;
        }
        if status.lines().next() != Some("sat") {
            return Ok(
                json!({"kind":"unresolved","reason":"solver-unknown-or-timeout","queries":queries}),
            );
        }
        let model = solve(root, &format!("{query}(get-value (target))\n"))?;
        let target = value(&model)?;
        targets.push(target);
        constraints.push_str(&format!(
            "(assert (distinct target (_ bv{target} {width})))\n"
        ));
    }
    targets.sort_unstable();
    targets.dedup();
    let kind = match (complete, targets.len()) {
        (true, 1) => "direct",
        (true, 2) => "conditional",
        _ => "computed-indirect",
    };
    let conditions = if kind == "conditional" {
        targets
            .iter()
            .map(|target| {
                json!({"target":format!("0x{target:x}"),
        "condition_smt2":format!("(= target (_ bv{target} {width}))")})
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    Ok(
        json!({"kind":kind,"targets":targets.iter().map(|target|format!("0x{target:x}")).collect::<Vec<_>>(),
        "target_set_complete":complete,"conditions":conditions,"queries":queries,
        "smt2_file":directory.join("branch.target.smt2"),"overapproximation":analysis["overapproximation"],
        "memory_inputs_independent":analysis["memory_inputs_independent"],
        "evidence":if complete{"finite-target-exclusion-query-unsat"}else{"at-least-three-abstract-target-models"},
        "feasibility_scope":"SSA-inputs-and-independent-memory-values; path correlations may overapproximate"}),
    )
}
