use core::borrow::{Borrow, BorrowMut};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ptr::null;

use bincode::Error;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rustc_serialize::hex::ToHex;
use secp256k1::PublicKey;
use secp256k1::{Message, Secp256k1, SecretKey, SerializedSignature, SignOnly, Signature};

use crate::block::Sha256Hash;
use crate::script_lang::{ScriptPubKey, ScriptSig, ScriptToken, StackValues};
use crate::wallet::{address_to_pub_hash, hash_pub_key, KeyHash, PubKeyBytes};

const SUBSIDY: u64 = 5000;

big_array! {
    BigArray;
    33,
    64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub id: Sha256Hash,
    pub vin: Vec<RefCell<TXInput>>,
    pub vout: Vec<TXOutput>,
}

impl Transaction {
    pub fn new_coinbase_tx(to: &String, data: String) -> Self {
        let mut data = data;
        if data == "".to_owned() {
            data = format!("Reward to {}", to)
        };
        let tx_in = TXInput {
            tx_id: Sha256Hash::default(),
            vout: -1,
            script_sig: ScriptSig {
                pub_key: [0; 33],
                signature: [0; 64],
            },
        };
        let tx_out = TXOutput::new(SUBSIDY, to);
        let mut tx = Self {
            id: Sha256Hash::default(),
            vin: vec![RefCell::new(tx_in)],
            vout: vec![tx_out],
        };
        tx.id = tx.hash();
        tx
    }
    pub fn new(vin: Vec<RefCell<TXInput>>, vout: Vec<TXOutput>) -> Self {
        let mut tx = Self {
            id: Sha256Hash::default(),
            vin: vin,
            vout,
        };
        tx.id = tx.hash();
        tx
    }
    fn hash(&self) -> Sha256Hash {
        let enc = match bincode::serialize(self) {
            Ok(enc_dat) => enc_dat,
            Err(e) => panic!("{}", e),
        };
        let mut hasher = Sha256::new();
        hasher.input(&enc);
        let mut hash = Sha256Hash::default();
        hasher.result(&mut hash);
        hash
    }

    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1
            && self.vin[0].borrow().tx_id == Sha256Hash::default()
            && self.vin[0].borrow().vout == -1
    }

    pub fn sign(
        &self,
        private_key: &SecretKey,
        prev_txs: HashMap<String, Transaction>,
    ) -> Option<Transaction> {
        if self.is_coinbase() {
            return None;
        }
        None
        //        let mut tx_copy = self.trimmed_copy();
        //
        //        for id in 0..tx_copy.vin.len() {
        //            {
        //                let mut vin = tx_copy.vin[id].borrow_mut();
        //                let prev_tx = &prev_txs[&vin.tx_id.to_hex()];
        //                vin.signature = [0; 64];
        //                vin.pub_key = Some(prev_tx.vout[vin.vout as usize].pub_key_hash);
        //            }
        //            tx_copy.id = tx_copy.hash();
        //            let mut vin = tx_copy.vin[id].borrow_mut();
        //            let sign = Secp256k1::signing_only();
        //            vin.signature = sign
        //                .sign(&Message::from_slice(&tx_copy.id).unwrap(), &private_key)
        //                .serialize_compact();
        //        }
        //        Some(tx_copy)
    }

    pub fn verify(&self, prev_txs: HashMap<String, Transaction>) -> bool {
        //        FIXME

        //        let mut tx_copy = self.trimmed_copy();
        //
        //        for (id, vin) in self.vin.iter().enumerate() {
        //            let borrow_vin = vin.borrow();
        //            {
        //                let mut vin_copy = tx_copy.vin[id].borrow_mut();
        //                let prev_tx = &prev_txs[&borrow_vin.tx_id.to_hex()];
        //
        //                vin_copy.signature = [0; 64];
        //                vin_copy.pub_key = Some(prev_tx.vout[borrow_vin.vout as usize].pub_key_hash);
        //            }
        //            tx_copy.id = tx_copy.hash();
        //            let sign = Secp256k1::verification_only();
        //            return true;
        //            //            if sign.verify(&Message::from_slice(&tx_copy.id).unwrap(),
        //            //                           &Signature::from_compact(&borrow_vin.signature).unwrap(),
        //            //                           &PublicKey::from_slice(&borrow_vin.pub_key.unwrap()).unwrap()).is_err()
        //            //            {
        //            //                return false;
        //            //            }
        //        }
        true
    }
    //        FIXME

    //    fn trimmed_copy(&self) -> Self {
    //        let mut inputs: Vec<RefCell<TXInput>> = Default::default();
    //        let mut outputs: Vec<TXOutput> = Default::default();
    //        for vin in self.vin.iter() {
    //            inputs.push(RefCell::new(TXInput {
    //                tx_id: vin.borrow().tx_id,
    //                vout: vin.borrow().vout.clone(),
    //                script_sig: ScriptSig {
    //                    pub_key: None,
    //                    signature: [0; 64],
    //                },
    //            }))
    //        }
    //        for vout in self.vout.iter() {
    //            outputs.push(TXOutput {
    //                value: vout.value,
    //                pub_key_hash: vout.pub_key_hash,
    //            })
    //        }
    //        Self {
    //            id: self.id,
    //            vin: inputs,
    //            vout: outputs,
    //        }
    //    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self, Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TXInput {
    pub tx_id: Sha256Hash,
    pub vout: i64,
    pub script_sig: ScriptSig,
}

impl TXInput {
    pub fn uses_key(&self, pub_key_hash: &KeyHash) -> bool {
        false
        //        FIXME

        //        self.pub_key == *pub_key_hash
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TXOutput {
    pub value: u64,
    pub script_pub_key: ScriptPubKey,
}

impl TXOutput {
    pub fn new(value: u64, address: &String) -> Self {
        Self {
            value,
            script_pub_key: pay_to_address_script(address),
        }
    }
    pub fn is_locker_with_key(&self, pub_key_hash: &KeyHash) -> bool {
        false
        //        FIXME
        //        self.pub_key_hash == *pub_key_hash
    }
}

fn pay_to_address_script(address: &String) -> ScriptPubKey {
    let pub_key_hash = address_to_pub_hash(address);
    ScriptPubKey {
        script: vec![
            ScriptToken::OpDup,
            ScriptToken::OpHash160,
            ScriptToken::Value(StackValues::PubKeyHash(pub_key_hash)),
        ],
    }
}

#[derive(Debug)]
pub enum TransactionError {
    NotEnoughMoney,
}
