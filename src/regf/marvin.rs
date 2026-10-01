//! Marvin32 hash (as used to protect new-format registry log entries).

#[inline]
fn block(p0: &mut u32, p1: &mut u32) {
    *p1 ^= *p0;
    *p0 = p0.rotate_left(20);
    *p0 = p0.wrapping_add(*p1);
    *p1 = p1.rotate_left(9);
    *p1 ^= *p0;
    *p0 = p0.rotate_left(27);
    *p0 = p0.wrapping_add(*p1);
    *p1 = p1.rotate_left(19);
}

/// Returns the 64-bit Marvin32 state `(p1 << 32) | p0`.
pub fn marvin32(seed: u64, data: &[u8]) -> u64 {
    let mut p0 = seed as u32;
    let mut p1 = (seed >> 32) as u32;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        p0 = p0.wrapping_add(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        block(&mut p0, &mut p1);
    }
    let rem = chunks.remainder();
    let fin: u32 = match rem.len() {
        0 => 0x80,
        1 => 0x8000 | rem[0] as u32,
        2 => 0x80_0000 | u16::from_le_bytes([rem[0], rem[1]]) as u32,
        _ => 0x8000_0000 | ((rem[2] as u32) << 16) | u16::from_le_bytes([rem[0], rem[1]]) as u32,
    };
    p0 = p0.wrapping_add(fin);
    block(&mut p0, &mut p1);
    block(&mut p0, &mut p1);
    ((p1 as u64) << 32) | p0 as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: u64 = 0x004F_B61A_001B_DBCC;

    // Known-answer tests from the .NET runtime Marvin test-suite.
    #[test]
    fn known_answers() {
        assert_eq!(marvin32(SEED, &[]), 0x30ED_35C1_00CD_3C7D);
        assert_eq!(marvin32(SEED, &[0xaf]), 0x48E7_3FC7_7D75_DDC1);
        assert_eq!(marvin32(SEED, &[0xe7, 0x0f]), 0xB5F6_E1FC_485D_BFF8);
        assert_eq!(marvin32(SEED, &[0x37, 0xf4, 0x95]), 0xF0B0_7C78_9B8C_F7E8);
        assert_eq!(
            marvin32(SEED, &[0x86, 0x42, 0xdc, 0x59]),
            0x7008_F2E8_7E9C_F556
        );
    }
}
