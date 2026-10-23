// SPDX-License-Identifier: Apache-2.0
mod ui;
use llmghidra_analysis::{ElfImage, Engine};
use std::{path::PathBuf, sync::Arc};
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|s| s == "--serve") {
        let result = args
            .get(1)
            .ok_or("usage: llmghidra-workbench --serve file.elf".into())
            .and_then(|path| ElfImage::open(PathBuf::from(path)))
            .and_then(|image| llmghidra_analysis::protocol::serve(Arc::new(Engine::new(image))));
        if let Err(e) = result {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }
    let screenshot = args
        .iter()
        .position(|a| a == "--screenshot")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let path = args
        .first()
        .filter(|s| !s.to_string_lossy().starts_with("--"))
        .map(PathBuf::from);
    let view = args
        .iter()
        .position(|a| a == "--view")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_string_lossy().into_owned());
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };
    if let Err(error) = eframe::run_native(
        "LLMGhidra — AI Analysis Workbench",
        options,
        Box::new(move |cc| Ok(Box::new(ui::Workbench::new(cc, path, screenshot, view)))),
    ) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
