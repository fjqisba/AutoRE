use anyhow::{Result, anyhow};
use inkwell::{context::Context, memory_buffer::MemoryBuffer};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ModuleSummary {
    pub verified: bool,
    pub functions: usize,
    pub triple: String,
    pub data_layout: String,
}

pub fn verify_bitcode(path: &Path) -> Result<ModuleSummary> {
    let context = Context::create();
    let buffer = MemoryBuffer::create_from_file(path).map_err(|err| anyhow!("{err}"))?;
    let module = inkwell::module::Module::parse_bitcode_from_buffer(&buffer, &context)
        .map_err(|err| anyhow!("{err}"))?;
    module.verify().map_err(|err| anyhow!("{err}"))?;
    Ok(ModuleSummary {
        verified: true,
        functions: module.get_functions().count(),
        triple: module.get_triple().as_str().to_string_lossy().into_owned(),
        data_layout: module
            .get_data_layout()
            .as_str()
            .to_string_lossy()
            .into_owned(),
    })
}

pub fn smoke_ir() -> Result<String> {
    let context = Context::create();
    let module = context.create_module("nereus_environment_check");
    let builder = context.create_builder();
    let i64_type = context.i64_type();
    let function = module.add_function(
        "wrapping_add",
        i64_type.fn_type(&[i64_type.into(), i64_type.into()], false),
        None,
    );
    builder.position_at_end(context.append_basic_block(function, "entry"));
    let lhs = function.get_nth_param(0).unwrap().into_int_value();
    let rhs = function.get_nth_param(1).unwrap().into_int_value();
    // 普通 add 保留机器整数回绕，不引入 nsw/nuw 假设。
    let sum = builder.build_int_add(lhs, rhs, "sum")?;
    builder.build_return(Some(&sum))?;
    module.verify().map_err(|err| anyhow!("{err}"))?;
    Ok(module.print_to_string().to_string())
}
