// SPDX-License-Identifier: Apache-2.0
mod support {
    pub mod fixture;
}
use llmghidra_analysis::{
    index::{store::Store, IndexSession},
    ElfImage,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
fn wait(session: &IndexSession) {
    let start = Instant::now();
    while session.progress().running {
        assert!(start.elapsed() < Duration::from_secs(30), "index timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn put(data: &mut [u8], offset: usize, value: u64, size: usize) {
    data[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
}
#[test]
fn automatic_index_recovers_functions_text_and_bidirectional_refs_and_resumes() {
    let mut data = support::fixture::fixture();
    put(&mut data, 24, 0, 8);
    put(&mut data, 60, 5, 2);
    for (base, va, off, flags) in [(0x32c0, 0x401000, 0x1000, 6), (0x3300, 0x402000, 0x2000, 2)] {
        put(&mut data, base + 4, 1, 4);
        put(&mut data, base + 8, flags, 8);
        put(&mut data, base + 16, va, 8);
        put(&mut data, base + 24, off, 8);
        put(&mut data, base + 32, 0x100, 8);
    }
    for (i, word) in [0xb0000000u64, 0x91000000, 0xf9400001, 0xd65f03c0]
        .into_iter()
        .enumerate()
    {
        put(&mut data, 0x1060 + i * 4, word, 4);
    }
    for (i, word) in "Hello UTF16".encode_utf16().chain([0]).enumerate() {
        put(&mut data, 0x2030 + i * 2, word as u64, 2);
    }
    // 两种编码分别跨越后台 256 KiB 分块边界，验证起点归属与去重。
    data.resize(0x84000, 0);
    put(&mut data, 152, 0x82000, 8);
    put(&mut data, 160, 0x82000, 8);
    put(&mut data, 0x3320, 0x82000, 8);
    let boundary_ascii = 0x2000 + 256 * 1024 - 3;
    data[boundary_ascii..boundary_ascii + 16].copy_from_slice(b"Boundary string\0");
    let boundary_utf16 = 0x2000 + 512 * 1024 - 4;
    for (i, word) in "Boundary UTF16".encode_utf16().chain([0]).enumerate() {
        put(&mut data, boundary_utf16 + i * 2, word as u64, 2);
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../temp_data/egui-workbench/tests");
    std::fs::create_dir_all(&base).unwrap();
    let file = base.join(format!("baseline-{}.elf", std::process::id()));
    std::fs::write(&file, &data).unwrap();
    let session = IndexSession::new(Arc::new(ElfImage::open(&file).unwrap())).unwrap();
    assert!(session.start());
    wait(&session);
    let progress = session.progress();
    assert!(progress.complete, "{:?}", progress);
    let store = Store::read(&session.path).unwrap();
    let functions = store.functions("helper", None, 128).unwrap();
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].address, 0x401040);
    let incoming = store.xrefs(0x401040, 0x401041, true, None, 128).unwrap();
    assert!(incoming
        .iter()
        .any(|x| x.from == 0x401004 && x.kind == "call"));
    let outgoing = store.xrefs(0x401004, 0x401005, false, None, 128).unwrap();
    assert!(outgoing.iter().any(|x| x.to == 0x401040));
    let strings = store.strings("Hello", None, 128).unwrap();
    assert!(strings
        .iter()
        .any(|s| s.address == 0x402000 && s.text == "Hello Android!"));
    assert!(strings
        .iter()
        .any(|s| s.address == 0x402030 && s.encoding == "UTF-16LE"));
    let cross = store.strings("Boundary", None, 128).unwrap();
    assert_eq!(
        cross
            .iter()
            .filter(|s| s.address == 0x402000 + 256 * 1024 - 3 && s.text == "Boundary string")
            .count(),
        1
    );
    assert_eq!(
        cross
            .iter()
            .filter(|s| s.address == 0x402000 + 512 * 1024 - 4 && s.text == "Boundary UTF16")
            .count(),
        1
    );
    let refs = store.xrefs(0x402000, 0x402001, true, None, 128).unwrap();
    assert!(refs
        .iter()
        .any(|x| x.from == 0x401064 && x.kind == "address"));
    assert!(refs.iter().any(|x| x.from == 0x401068 && x.kind == "read"));
    std::thread::sleep(Duration::from_millis(5));
    assert!(session.start());
    wait(&session);
    let second = session.progress();
    assert_eq!(progress.counts.functions, second.counts.functions);
    assert_eq!(progress.counts.xrefs, second.counts.xrefs);
    assert_eq!(progress.counts.strings, second.counts.strings);
    let restored = IndexSession::restore(
        session.path.clone(),
        &llmghidra_analysis::Cancellation::default(),
    )
    .unwrap();
    assert_eq!(restored.progress().counts.xrefs, progress.counts.xrefs);
    drop(restored);
    drop(store);
    drop(session);
    std::fs::remove_file(file).unwrap();
}
