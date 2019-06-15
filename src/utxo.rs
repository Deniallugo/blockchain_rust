use core::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;

use bincode::Error;
use rkv::{RoCursor, StoreOptions, Value};
use rustc_serialize::hex::ToHex;

use crate::blockchain::Blockchain;
use crate::transaction::TXOutput;
use crate::wallet::KeyHash;

struct UTXOSet<'a> {
    blockchain: &'a mut Blockchain,
}

#[derive(Serialize, Deserialize, Clone)]
struct OutsSet {
    outs: Vec<TXOutput>,
}

impl OutsSet {
    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self, Error> {
        bincode::deserialize(bytes)
    }
}

const UTXOBUCKET: &str = "utxo";

impl<'a> UTXOSet<'a> {
    fn reindex(self) {
        let env = self.blockchain.store.rkv();
        let store = env.open_single(UTXOBUCKET, StoreOptions::create()).unwrap();
        let mut writer = env.write().unwrap();
        store.clear(&mut writer).unwrap();
        //        utxo = self.find_utxo()
        //        store.delete(writer, UTXOBUCKET)
    }

    fn find_spendable_outputs(
        &self,
        pub_key_hash: KeyHash,
        amount: u64,
    ) -> (u64, HashMap<String, Vec<usize>>) {
        let mut unspent_outputs: HashMap<String, Vec<usize>> = Default::default();

        let mut accumulated: u64 = 0;
        let env = self.blockchain.store.rkv();
        let store = env.open_single(UTXOBUCKET, StoreOptions::create()).unwrap();
        let reader = env.read().unwrap();

        let mut iter = store.iter_start(&reader).unwrap();
        while let Some(Ok((tx_id, Some(Value::Blob(tx))))) = iter.next() {
            let outs = OutsSet::from_bytes(&tx.to_vec()).unwrap().outs;
            let tx_hex = tx_id.to_hex();
            for (out_idx, out) in outs.iter().enumerate() {
                if out.is_locker_with_key(&pub_key_hash) && accumulated < amount {
                    accumulated += out.value;
                    let mut unspent_out_in_tx = unspent_outputs
                        .entry(tx_hex.clone())
                        .or_insert(Default::default());

                    (*unspent_out_in_tx).push(out_idx);
                }
            }
        }
        (accumulated, unspent_outputs)
    }
    fn find_utxo(&self, pub_key_hash: KeyHash) -> Vec<TXOutput> {
        let mut utxo: Vec<TXOutput> = Default::default();

        let env = self.blockchain.store.rkv();
        let store = env.open_single(UTXOBUCKET, StoreOptions::create()).unwrap();
        let reader = env.read().unwrap();

        let mut iter = store.iter_start(&reader).unwrap();
        while let Some(Ok((tx_id, Some(Value::Blob(tx))))) = iter.next() {
            let outs = OutsSet::from_bytes(&tx.to_vec()).unwrap().outs;
            for out in outs {
                if out.is_locker_with_key(&pub_key_hash) {
                    utxo.push(out)
                }
            }
        }
        utxo
    }
}
