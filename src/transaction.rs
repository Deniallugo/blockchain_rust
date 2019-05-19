use crypto::digest::Digest;
use crypto::sha2::Sha256;

use crate::block::Sha256Hash;

const SUBSIDY: u64 = 5000;

#[derive(Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub id: Sha256Hash,
    pub vin: Vec<TXInput>,
    pub vout: Vec<TXOutput>,

}


impl Transaction {
    pub(crate) fn new_coinbase_tx(to: String, data: String) -> Self {
        let mut data = data;
        if data == "" {
            data = format!("Reward to {}", to)
        };
        let tx_in = TXInput {
            tx_id: Sha256Hash::default(),
            vout: -1,
            script_sig: data,
        };
        let tx_out = TXOutput {
            value: SUBSIDY,
            script_pub_key: to,
        };
        let mut tx = Self {
            id: Sha256Hash::default(),
            vin: vec![tx_in],
            vout: vec![tx_out],
        };
        tx.set_id();
        tx
    }
    pub fn new(vin: Vec<TXInput>, vout: Vec<TXOutput>) -> Self {
        let mut tx = Self {
            id: Sha256Hash::default(),
            vin,
            vout,
        };
        tx.set_id();
        tx
    }
    fn set_id(&mut self) {
        let enc = bincode::serialize(self).unwrap();
        let mut hasher = Sha256::new();
        hasher.input(&enc);
        let mut hash = Sha256Hash::default();
        hasher.result(&mut hash);
        self.id = hash;
    }
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].tx_id == Sha256Hash::default() && self.vin[0].vout == -1
    }
}


#[derive(Serialize, Deserialize, Clone)]
pub struct TXInput {
    pub tx_id: Sha256Hash,
    pub vout: i64,
    pub script_sig: String,
}

impl TXInput {
    pub fn can_unlock_output_with(&self, unlock_data: &String) -> bool {
        self.script_sig == *unlock_data
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TXOutput {
    pub value: u64,
    pub script_pub_key: String,
}

impl TXOutput {
    pub fn can_be_unlocked_with(&self, unlock_data: &String) -> bool {
        self.script_pub_key == *unlock_data
    }
}

#[derive(Debug)]
pub enum TransactionError {
    NotEnoughMoney
}