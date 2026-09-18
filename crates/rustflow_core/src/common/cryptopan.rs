//! Crypto-PAn: prefix-preserving IP address anonymization (Xu, Fan, Ammar
//! and Moon, 2002). Two addresses that share their first `n` bits are
//! mapped to addresses that share their first `n` bits, so subnet
//! structure survives while the addresses themselves do not.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

/// The 32-byte key: 16 bytes of AES key followed by 16 bytes that seed the
/// padding block.
pub const KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct CryptoPan {
    cipher: Aes128,
    /// The encrypted second half of the key, as the reference does it.
    pad: u128,
}

impl CryptoPan {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let (aes_key, pad_seed): (&[u8; 16], &[u8; 16]) = key
            .split_first_chunk()
            .map(|(head, tail)| (head, tail.try_into().expect("32 - 16 = 16 bytes")))
            .expect("key is 32 bytes");
        let cipher = Aes128::new(&Array::from(*aes_key));
        let mut pad = Array::from(*pad_seed);
        cipher.encrypt_block(&mut pad);
        Self {
            cipher,
            pad: u128::from_be_bytes(pad.into()),
        }
    }

    pub fn anonymize(&self, addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V4(v4) => IpAddr::V4(self.anonymize_v4(v4)),
            IpAddr::V6(v6) => IpAddr::V6(self.anonymize_v6(v6)),
        }
    }

    /// An IPv4 address is the first 32 bits of the 128-bit block, the rest
    /// of the block is padding, exactly as in the reference.
    pub fn anonymize_v4(&self, addr: Ipv4Addr) -> Ipv4Addr {
        let bits = u128::from(u32::from(addr)) << 96;
        let out = self.anonymize_bits(bits, 32);
        Ipv4Addr::from((out >> 96) as u32)
    }

    pub fn anonymize_v6(&self, addr: Ipv6Addr) -> Ipv6Addr {
        Ipv6Addr::from(self.anonymize_bits(u128::from(addr), 128))
    }

    /// Bit `i` of the output is bit `i` of the input flipped by the first
    /// bit of `AES(prefix of length i || padding)`. The flip depends only on
    /// the prefix, which is what preserves prefixes.
    fn anonymize_bits(&self, addr: u128, bits: u32) -> u128 {
        let mut flips = 0u128;
        for i in 0..bits {
            let prefix_mask = if i == 0 { 0 } else { u128::MAX << (128 - i) };
            let input = (addr & prefix_mask) | (self.pad & !prefix_mask);
            let mut block = Array::from(input.to_be_bytes());
            self.cipher.encrypt_block(&mut block);
            let flip = u128::from(block[0] >> 7);
            flips |= flip << (127 - i);
        }
        addr ^ flips
    }
}
