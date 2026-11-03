// SPDX-License-Identifier: Apache-2.0
pub fn fixture() -> Vec<u8> {
    let mut data = vec![0u8; 0x3400];
    data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    fn put(data: &mut [u8], at: usize, n: u64, size: usize) {
        data[at..at + size].copy_from_slice(&n.to_le_bytes()[..size]);
    }
    for (at, n, size) in [
        (16, 2, 2),
        (18, 183, 2),
        (20, 1, 4),
        (24, 0x401000, 8),
        (32, 64, 8),
        (40, 0x3200, 8),
        (52, 64, 2),
        (54, 56, 2),
        (56, 2, 2),
        (58, 64, 2),
        (60, 3, 2),
    ] {
        put(&mut data, at, n, size);
    }
    for (at, n, size) in [
        (64, 1, 4),
        (68, 5, 4),
        (72, 0x1000, 8),
        (80, 0x401000, 8),
        (96, 0x100, 8),
        (104, 0x1000, 8),
        (112, 0x1000, 8),
        (120, 1, 4),
        (124, 6, 4),
        (128, 0x2000, 8),
        (136, 0x402000, 8),
        (152, 0x1400, 8),
        (160, 0x2000, 8),
        (168, 0x1000, 8),
    ] {
        put(&mut data, at, n, size);
    }
    for at in (0x1000..0x1100).step_by(4) {
        put(&mut data, at, 0xd503201f, 4);
    }
    // mov x0,#5; bl helper; cbz x0,zero; add x0,x0,#1; ret; zero: mov x0,#0; ret.
    for (i, word) in [
        0xd28000a0, 0x9400000f, 0xb4000060, 0x91000400, 0xd65f03c0, 0xd2800000, 0xd65f03c0,
    ]
    .iter()
    .enumerate()
    {
        put(&mut data, 0x1000 + i * 4, *word, 4);
    }
    put(&mut data, 0x1040, 0x91000800, 4);
    put(&mut data, 0x1044, 0xd65f03c0, 4);
    data[0x2000..0x2010].copy_from_slice(b"Hello Android!\0\0");
    // 三个 section：NULL / SYMTAB / STRTAB；完全不要求 section 名字表。
    for (at, n, size) in [
        (0x3244, 2, 4),
        (0x3258, 0x3000, 8),
        (0x3260, 72, 8),
        (0x3268, 2, 4),
        (0x3278, 24, 8),
        (0x3284, 3, 4),
        (0x3298, 0x3100, 8),
        (0x32a0, 13, 8),
    ] {
        put(&mut data, at, n, size);
    }
    data[0x3100..0x310d].copy_from_slice(b"\0main\0helper\0");
    for (at, n, size) in [
        (0x3018, 1, 4),
        (0x301c, 0x12, 1),
        (0x301e, 1, 2),
        (0x3020, 0x401000, 8),
        (0x3028, 28, 8),
        (0x3030, 6, 4),
        (0x3034, 0x12, 1),
        (0x3036, 1, 2),
        (0x3038, 0x401040, 8),
        (0x3040, 8, 8),
    ] {
        put(&mut data, at, n, size);
    }
    data
}
