//! Wire format for the list of deleted chunks (tombstones) that the server hands to a client
//! so it can invalidate its local "does this chunk exist remotely" cache after a prune.
//!
//! The payload is an ascending, deduplicated list of truncated chunk hashes, delta encoded as
//! LEB128 varints. Sorting is what makes this small: consecutive entries differ by only
//! `2^prefix_bits / count` on average, so each entry costs roughly
//! `log2(2^prefix_bits / count)` bits instead of `prefix_bits`.
//!
//! Truncating the hash means a client can see a match for a chunk that was not actually
//! deleted. That is safe: the client marks the chunk absent and re-uploads it, and the server
//! answers `409 Already there`. The expected number of such false matches is
//! `working_set * deleted / 2^prefix_bits`, which is about 3 for our largest deployment at 48
//! bits.

#![allow(dead_code)]

/// Magic identifying the payload format. Bump the trailing digit on an incompatible change.
pub const MAGIC: &[u8; 6] = b"MBDEL1";

/// magic + prefix_bits + flags + last_id + count
pub const HEADER_LEN: usize = 6 + 1 + 1 + 8 + 8;

/// Number of leading hash bits exchanged. Carried in the header so it can be changed without
/// breaking the protocol.
pub const DEFAULT_PREFIX_BITS: u8 = 48;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TombstoneError {
    BadMagic,
    UnsupportedPrefixBits(u8),
    UnsupportedFlags(u8),
    Truncated,
    TrailingData,
    NotAscending,
    ValueTooLarge,
    CountMismatch,
}

impl std::fmt::Display for TombstoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TombstoneError::BadMagic => write!(f, "bad magic"),
            TombstoneError::UnsupportedPrefixBits(b) => write!(f, "unsupported prefix bits {b}"),
            TombstoneError::UnsupportedFlags(b) => write!(f, "unsupported flags {b:#x}"),
            TombstoneError::Truncated => write!(f, "truncated payload"),
            TombstoneError::TrailingData => write!(f, "trailing data after payload"),
            TombstoneError::NotAscending => write!(f, "entries are not strictly ascending"),
            TombstoneError::ValueTooLarge => write!(f, "entry does not fit in prefix_bits"),
            TombstoneError::CountMismatch => write!(f, "count does not match payload"),
        }
    }
}

impl std::error::Error for TombstoneError {}

/// Reduce the top 64 bits of a hash to the leading `bits` bits.
pub fn truncate(prefix64: u64, bits: u8) -> u64 {
    if bits >= 64 {
        prefix64
    } else {
        prefix64 >> (64 - bits)
    }
}

/// The top 64 bits of a hex encoded hash, or `None` if it is not at least 16 hex characters.
pub fn hash_prefix64(hash: &str) -> Option<u64> {
    let head = hash.get(0..16)?;
    u64::from_str_radix(head, 16).ok()
}

/// The leading `bits` bits of a hex encoded hash.
pub fn prefix_of_hex(hash: &str, bits: u8) -> Option<u64> {
    Some(truncate(hash_prefix64(hash)?, bits))
}

/// Write a u64 as a LEB128 varint to `out`.
fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Read a LEB128 varint from `data` starting at `pos`, advancing `pos` past the varint.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, TombstoneError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*pos).ok_or(TombstoneError::Truncated)?;
        *pos += 1;
        if shift >= 64 || (shift == 63 && byte > 1) {
            return Err(TombstoneError::ValueTooLarge);
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

/// Encode `values` (already truncated to `prefix_bits`) as a tombstone payload.
/// The slice is sorted and deduplicated in place.
pub fn encode(values: &mut Vec<u64>, prefix_bits: u8, last_id: i64) -> Vec<u8> {
    assert!(prefix_bits > 0 && prefix_bits <= 64);
    values.sort_unstable();
    values.dedup();
    let mut out = Vec::with_capacity(HEADER_LEN + values.len() * 6);
    out.extend_from_slice(MAGIC);
    out.push(prefix_bits);
    out.push(0);
    out.extend_from_slice(&last_id.to_le_bytes());
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    let mut prev = 0u64;
    for &v in values.iter() {
        write_varint(&mut out, v - prev);
        prev = v;
    }
    out
}

#[derive(Debug)]
pub struct Decoded {
    pub prefix_bits: u8,
    /// Sequence number the client should record once it has applied `values`.
    pub last_id: i64,
    /// Ascending, deduplicated, each strictly less than `2^prefix_bits`.
    pub values: Vec<u64>,
}

pub fn decode(data: &[u8]) -> Result<Decoded, TombstoneError> {
    if data.len() < HEADER_LEN {
        return Err(TombstoneError::Truncated);
    }
    if &data[0..6] != MAGIC {
        return Err(TombstoneError::BadMagic);
    }
    let prefix_bits = data[6];
    if prefix_bits == 0 || prefix_bits > 64 {
        return Err(TombstoneError::UnsupportedPrefixBits(prefix_bits));
    }
    let flags = data[7];
    if flags != 0 {
        return Err(TombstoneError::UnsupportedFlags(flags));
    }
    let last_id = i64::from_le_bytes(data[8..16].try_into().unwrap());
    let count = u64::from_le_bytes(data[16..24].try_into().unwrap());

    let payload = &data[HEADER_LEN..];
    // count is attacker controlled, so bound the allocation by what the payload could hold:
    // every entry costs at least one byte.
    if count > payload.len() as u64 {
        return Err(TombstoneError::CountMismatch);
    }

    let mut values = Vec::with_capacity(count as usize);
    let mut pos = 0usize;
    let mut prev = 0u64;
    for i in 0..count {
        let delta = read_varint(payload, &mut pos)?;
        if i > 0 && delta == 0 {
            return Err(TombstoneError::NotAscending);
        }
        let v = prev
            .checked_add(delta)
            .ok_or(TombstoneError::ValueTooLarge)?;
        if prefix_bits < 64 && (v >> prefix_bits) != 0 {
            return Err(TombstoneError::ValueTooLarge);
        }
        values.push(v);
        prev = v;
    }
    if pos != payload.len() {
        return Err(TombstoneError::TrailingData);
    }
    Ok(Decoded {
        prefix_bits,
        last_id,
        values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(mut values: Vec<u64>, bits: u8, last_id: i64) -> Decoded {
        let mut expected = values.clone();
        expected.sort_unstable();
        expected.dedup();
        let encoded = encode(&mut values, bits, last_id);
        let decoded = decode(&encoded).expect("decode failed");
        assert_eq!(decoded.prefix_bits, bits);
        assert_eq!(decoded.last_id, last_id);
        assert_eq!(decoded.values, expected);
        decoded
    }

    #[test]
    fn empty() {
        let decoded = roundtrip(Vec::new(), 48, 0);
        assert!(decoded.values.is_empty());
    }

    #[test]
    fn single() {
        roundtrip(vec![1], 48, 7);
        roundtrip(vec![(1u64 << 48) - 1], 48, 7);
        roundtrip(vec![0], 48, 7);
    }

    #[test]
    fn sorts_and_dedups() {
        roundtrip(vec![5, 1, 5, 3, 1], 48, 42);
    }

    #[test]
    fn maximal_gaps() {
        roundtrip(vec![0, (1u64 << 48) - 1], 48, -1);
        roundtrip(vec![0, u64::MAX], 64, i64::MAX);
    }

    #[test]
    fn many_entries() {
        // Deterministic pseudo random spread, similar density to a real prune.
        let mut v: Vec<u64> = Vec::new();
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..10_000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            v.push(truncate(x, 48));
        }
        let decoded = roundtrip(v, 48, 99);
        assert!(decoded.values.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut encoded = encode(&mut vec![1, 2, 3], 48, 0);
        encoded[0] = b'X';
        assert_eq!(decode(&encoded).unwrap_err(), TombstoneError::BadMagic);
    }

    #[test]
    fn rejects_truncated() {
        let encoded = encode(&mut vec![1, 300, 70000], 48, 0);
        for cut in 0..encoded.len() {
            assert!(decode(&encoded[..cut]).is_err(), "cut at {cut} decoded");
        }
    }

    #[test]
    fn rejects_unknown_flags() {
        let mut encoded = encode(&mut vec![1, 2], 48, 0);
        encoded[7] = 1;
        assert_eq!(
            decode(&encoded).unwrap_err(),
            TombstoneError::UnsupportedFlags(1)
        );
    }

    #[test]
    fn rejects_value_wider_than_prefix() {
        let encoded = encode(&mut vec![1u64 << 40], 48, 0);
        let mut narrowed = encoded.clone();
        narrowed[6] = 32;
        assert_eq!(
            decode(&narrowed).unwrap_err(),
            TombstoneError::ValueTooLarge
        );
    }

    #[test]
    fn rejects_count_larger_than_payload() {
        let mut encoded = encode(&mut vec![1, 2], 48, 0);
        encoded[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode(&encoded).unwrap_err(), TombstoneError::CountMismatch);
    }

    #[test]
    fn prefix_extraction() {
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(hash_prefix64(hash), Some(0x0123_4567_89ab_cdef));
        assert_eq!(prefix_of_hex(hash, 48), Some(0x0123_4567_89ab));
        assert_eq!(prefix_of_hex(hash, 64), Some(0x0123_4567_89ab_cdef));
        assert_eq!(hash_prefix64("abc"), None);
    }

    #[test]
    fn hex_string_order_matches_numeric_order() {
        // The client merge join relies on lowercase hex sorting the same way as the numbers.
        let mut hex: Vec<String> = Vec::new();
        let mut x: u64 = 0xdead_beef_0bad_f00d;
        for _ in 0..1000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            hex.push(format!("{x:016x}"));
        }
        let mut nums: Vec<u64> = hex.iter().map(|h| hash_prefix64(h).unwrap()).collect();
        hex.sort();
        nums.sort_unstable();
        let from_hex: Vec<u64> = hex.iter().map(|h| hash_prefix64(h).unwrap()).collect();
        assert_eq!(from_hex, nums);
    }
}
