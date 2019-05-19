extern crate bincode;

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::Error;

use crate::mining_error::MiningError;
use crate::proof_of_work::{convert_u64_to_u8_array, ProofOfWork, TARGET_BITS};

const HASH_BYTE_SIZE: usize = 32;

pub type Sha256Hash = [u8; HASH_BYTE_SIZE];

#[derive(Serialize, Deserialize)]
pub struct Block {
    pub timestamp: u64,
    pub data: Vec<u8>,
    pub hash: Sha256Hash,
    pub prev_block_hash: Sha256Hash,
    pub nonce: u64,
}


impl Block {
    pub fn new(data: String, prev_block_hash: Sha256Hash) -> Result<Self, MiningError> {
        let data_bytes = data.into();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut block = Self {
            timestamp,
            data: data_bytes,
            prev_block_hash,
            hash: Default::default(),
            nonce: 0,
        };

        let pow = ProofOfWork::new(&block);
        let (nonce, hash) = pow.run()?;
        block.hash = hash;
        block.nonce = nonce;
        Ok(block)
    }

    pub(crate) fn headers(&self) -> Vec<u8> {
        let mut vec = Vec::new();

        vec.extend(&convert_u64_to_u8_array(self.timestamp));
        vec.extend(&convert_u64_to_u8_array(TARGET_BITS));
        vec.extend(&self.prev_block_hash);
        vec.extend(&self.data);
        vec
    }
    pub fn genesis_block() -> Result<Self, MiningError> {
        Self::new(String::from("Genesis Block"), Sha256Hash::default())
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
                Data: {:?} \n \
                nonce: {}",
               self.hash,
               self.prev_block_hash,
               self.timestamp,
               String::from_utf8_lossy(&self.data),
               self.nonce)
    }
}