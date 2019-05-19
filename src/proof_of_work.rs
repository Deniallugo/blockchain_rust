use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num_bigint::BigUint;
use num_bigint::ToBigUint;

use crate::block::{Block, Sha256Hash};
use crate::mining_error::MiningError;

pub(crate) const TARGET_BITS: u64 = 15;
const MAX_NONCE: u64 = 1_000_000;

pub struct ProofOfWork<'a> {
    block: &'a Block,
    target: BigUint,
}

impl<'a> ProofOfWork<'a> {
    pub fn new(block: &Block) -> ProofOfWork {
        let target = 1_u64.to_biguint().unwrap();
        let shift_target: BigUint = target << (256 - TARGET_BITS) as usize;
        ProofOfWork {
            block,
            target: shift_target,
        }
    }

    pub fn validate(&self) -> bool {
        let hash = self.calculate_hash(self.block.nonce);
        let hash_int = BigUint::from_bytes_be(&hash);
        hash_int <= self.target
    }

    pub fn run(&self) -> Result<(u64, Sha256Hash), MiningError> {
        for nonce in 0..MAX_NONCE {
            let hash = self.calculate_hash(nonce);
            let hash_int = BigUint::from_bytes_be(&hash);
            if hash_int <= self.target {
                return Ok((nonce, hash));
            }
        }
        Err(MiningError::Iteration)
    }

    fn calculate_hash(&self, nonce: u64) -> Sha256Hash {
        let mut headers = self.block.headers();
        headers.extend_from_slice(&convert_u64_to_u8_array(nonce));

        let mut hasher = Sha256::new();
        hasher.input(&headers);
        let mut hash = Sha256Hash::default();
        hasher.result(&mut hash);
        hash
    }
}


pub fn convert_u64_to_u8_array(val: u64) -> [u8; 8] {
    return [
        val as u8,
        (val >> 8) as u8,
        (val >> 16) as u8,
        (val >> 24) as u8,
        (val >> 32) as u8,
        (val >> 40) as u8,
        (val >> 48) as u8,
        (val >> 56) as u8,
    ];
}

