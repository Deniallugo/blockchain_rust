use core::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::HashMap;

use bincode::Error;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rustc_serialize::hex::ToHex;
use secp256k1::{Message, Secp256k1, SecretKey};

use crate::block::Sha256Hash;
use crate::script_lang::{
	pay_to_address_script, ScriptPubKey, ScriptSig, ScriptToken, StackValues,
};
use crate::wallet::{
	KeyHash, private_key_to_public, PubKeyBytes,
};
use crate::wallet::Wallet;

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
		prev_txs: &HashMap<String, Transaction>,
	) -> Option<Transaction> {
		if self.is_coinbase() {
			return None;
		}
		let tx_copy = self.trimmed_copy();
		for id in 0..tx_copy.vin.len() {
			{
				let mut vin = tx_copy.vin[id].borrow_mut();
				let _prev_tx = &prev_txs[&vin.tx_id.to_hex()];
				vin.script_sig = ScriptSig {
					signature: [0; 64],
					pub_key: private_key_to_public(private_key),
				};
			}
			let mut vin = tx_copy.vin[id].borrow_mut();
			let sign = Secp256k1::signing_only();
			println!("Msg for sign {:?}", &tx_copy.id.to_vec());
			println!("Key for sign {:?}", &vin.script_sig.pub_key.to_vec());
			vin.script_sig.signature = sign
				.sign(&Message::from_slice(&tx_copy.id).unwrap(), private_key)
				.serialize_compact();
			println!("Sign for sign {:?}", &vin.script_sig.signature.to_vec());
		}
		Some(tx_copy)
	}

	pub fn verify(&self, prev_txs: &HashMap<String, Transaction>) -> bool {
		let tx_copy = self.trimmed_copy();

		for (_id, vin) in self.vin.iter().enumerate() {
			let borrow_vin = vin.borrow();
			let prev_tx = &prev_txs[&borrow_vin.tx_id.to_hex()];

			let script_pub_key = &prev_tx.vout[borrow_vin.vout as usize].script_pub_key;

			if let Ok(result) =
			script_pub_key.verify(Some(&borrow_vin.script_sig), Some(&tx_copy.id))
			{
				if result {
					continue;
				} else {
					return false;
				}
			} else {
				return false;
			}
		}
		true
	}

	fn trimmed_copy(&self) -> Self {
		let mut inputs: Vec<RefCell<TXInput>> = Default::default();
		let mut outputs: Vec<TXOutput> = Default::default();
		for vin in self.vin.iter() {
			let borrow_vin = vin.borrow();
			inputs.push(RefCell::new(TXInput {
				tx_id: borrow_vin.tx_id,
				vout: borrow_vin.vout.clone(),
				script_sig: ScriptSig {
					pub_key: [0; 33],
					signature: [0; 64],
				},
			}))
		}
		for vout in self.vout.iter() {
			outputs.push(TXOutput {
				value: vout.value,
				script_pub_key: vout.script_pub_key.clone(),
			})
		}
		Self {
			id: self.id,
			vin: inputs,
			vout: outputs,
		}
	}

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
	pub fn uses_key(&self, pub_key: &PubKeyBytes) -> bool {
		//        FIXME
		self.script_sig.pub_key.to_vec() == pub_key.to_vec()
	}
	pub fn new(income_transaction: &Transaction, vout: i64, from: &Wallet) -> Self {
		Self {
			script_sig: ScriptSig {
				pub_key: from.public_key,
				signature: from.sign(income_transaction.id.to_vec()),
			},
			vout,
			tx_id: income_transaction.id,
		}
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
		for token in &self.script_pub_key.script {
			if let ScriptToken::Value(StackValues::PubKeyHash(find_hash)) = token {
				if find_hash == pub_key_hash {
					return true;
				}
			}
		}
		false
	}
}

#[derive(Debug)]
pub enum TransactionError {
	NotEnoughMoney,
}

#[cfg(test)]
mod tests {
	use crate::wallet::Wallet;

	use super::*;

	#[test]
	fn sign_transaction() {
		let from = Wallet::new();
		let to = Wallet::new();
		let coinbase = Transaction::new_coinbase_tx(&from.get_address(), "".to_string());

		let out = TXOutput::new(10, &to.get_address());
		let in_tx = TXInput::new(&coinbase, 0, &from);
		let tx = Transaction::new(vec![RefCell::new(in_tx)], vec![out]);

		let mut prev_txs = HashMap::new();
		prev_txs.insert(coinbase.id.to_hex(), coinbase);
		let signed_tx = tx.sign(&from.private_key(), &prev_txs).unwrap();
		assert_eq!(signed_tx.verify(&prev_txs), true)
	}
}
