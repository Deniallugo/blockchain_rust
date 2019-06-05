extern crate bincode;

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::Error;

use crate::mining_error::MiningError;
use crate::proof_of_work::{convert_u64_to_u8_array, ProofOfWork, TARGET_BITS};
use crate::transaction::Transaction;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use rustc_serialize::hex::ToHex;

const HASH_BYTE_SIZE: usize = 32;

pub type Sha256Hash = [u8; HASH_BYTE_SIZE];

#[derive(Serialize, Deserialize)]
pub struct Block {
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub hash: Sha256Hash,
    pub prev_block_hash: Sha256Hash,
    pub nonce: u64,
}


impl Block {
    pub fn new(transactions: Vec<Transaction>, prev_block_hash: Sha256Hash) -> Result<Self, MiningError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut block = Self {
            timestamp,
            transactions,
            prev_block_hash,
            hash: Sha256Hash::default(),
            nonce: 0,
        };

        let pow = ProofOfWork::new(&block);
        let (nonce, hash) = pow.run()?;
        block.hash = hash;
        block.nonce = nonce;
        Ok(block)
    }
    fn hash_transactions(&self) -> Sha256Hash {
        let mut tx_hashes= Vec::new();
        for tx in &self.transactions {
            tx_hashes.extend(&tx.id);
        }
        let mut hasher = Sha256::new();
        hasher.input(&tx_hashes);
        let mut hash = Sha256Hash::default();
        hasher.result(&mut hash);
        hash
    }
    pub(crate) fn headers(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(&convert_u64_to_u8_array(self.timestamp));
        vec.extend(&convert_u64_to_u8_array(TARGET_BITS));
        vec.extend(&self.prev_block_hash);
        vec.extend(&self.hash_transactions());
        vec
    }
    pub fn genesis_block(coinbase: Transaction) -> Result<Self, MiningError> {
        Self::new(vec![Transaction::from(coinbase)], Sha256Hash::default())
    }
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self, Error> {
        bincode::deserialize(bytes)
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "Hash: {:?} \n \
                Prev Hash: {:?} \n \
                Timestamp: {} \n \
                nonce: {}",
               self.hash.to_hex(),
               self.prev_block_hash.to_hex(),
               self.timestamp,
               self.nonce)
    }
}