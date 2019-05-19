use std::collections::HashMap;

use rkv::Value;
use rustc_serialize::hex::{FromHex, ToHex};

use crate::block::{Block, Sha256Hash};
use crate::mining_error::MiningError;
use crate::store::Store;
use crate::transaction::{Transaction, TransactionError, TXInput, TXOutput};

pub struct Blockchain {
    tip: Option<Sha256Hash>,
    path: String,
    store: Store,
}

impl Blockchain {
    pub fn new(path_str: String, address: String) -> Result<Blockchain, MiningError> {
        let store = Store::new(&path_str, "block".to_owned());
        let env = store.rkv();
        let single_store = store.single_store();
        let reader = env.read().unwrap();

        let mut gen_block;

        let tip = match single_store.get(&reader, "l") {
            Ok(l_opt) => match l_opt {
                Some(l) => match l {
                    Value::Blob(val) => {
                        let mut a: [u8; 32] = Default::default();
                        a.copy_from_slice(val);
                        a
                    }
                    _ => panic!("Wrong format")
                },
                None => {
                    let coinbase_transaction =
                        Transaction::new_coinbase_tx(address,
                                                     "genesis block".to_string());
                    gen_block = Block::genesis_block(coinbase_transaction)?;
                    let mut writer = env.write().unwrap();
                    single_store.put(&mut writer, &gen_block.hash, &Value::Blob(&gen_block.serialize())).unwrap();
                    single_store.put(&mut writer, "l", &Value::Blob(&gen_block.hash)).unwrap();
                    writer.commit().unwrap();
                    gen_block.hash
                }
            }
            Err(e) => {
                panic!("{}", e);
            }
        };
        Ok(Blockchain {
            store: Store::clone(&store),
            path: path_str,
            tip: Some(tip),
        })
    }
    pub fn mine_block(&mut self, transactions: Vec<Transaction>) -> Result<(), MiningError> {
        let mut block: Block;

        let rkv = self.store.rkv();
        let single_store = self.store.single_store();

        match self.tip {
            Some(hash) => {
                block = Block::new(transactions, hash)?;
                let mut writer = rkv.write().unwrap();
                single_store.put(&mut writer, &block.hash, &Value::Blob(&block.serialize())).unwrap();
                single_store.put(&mut writer, "l", &Value::Blob(&block.hash)).unwrap();
                writer.commit().unwrap();
            }
            None => {
                return Err(MiningError::NoParent);
            }
        }
        self.tip = Some(block.hash);
        Ok(())
    }
    pub fn find_unspent_transactions(&self, address: &String) -> Vec<Transaction> {
        let mut unspent_txs: Vec<Transaction> = vec![];
        let mut spent_txs: HashMap<String, Vec<i64>> = HashMap::new();
        for block in self.iter() {
            for tx in block.transactions {
                let tx_id = tx.id.to_hex();
                'outs: for (out_idx, out) in tx.vout.iter().enumerate() {
                    match spent_txs.get(&tx_id) {
                        Some(spent_outs) => {
                            for val in spent_outs {
                                if *val == out_idx as i64 { continue 'outs; }
                            }
                        }
                        None => ()
                    }

                    if out.can_be_unlocked_with(address) {
                        unspent_txs.push(tx.clone()) // Ask about it, can i save it better?
                    }
                    if !tx.is_coinbase() {
                        for vin in &tx.vin {
                            if vin.can_unlock_output_with(address) {
                                let in_tx_id = vin.tx_id.to_hex();

                                match spent_txs.get_mut(&in_tx_id) {
                                    Some(vec) => vec.push(vin.vout),
                                    None => { spent_txs.insert(in_tx_id, vec![vin.vout]); }
                                }
                            }
                        }
                    }
                    if block.prev_block_hash.len() == 0 {
                        break;
                    }
                }
            }
        }
        unspent_txs
    }
    pub fn find_outs(self, address: &String) -> Vec<TXOutput> {
        let mut outs: Vec<TXOutput> = vec![];
        let unspent_txs = self.find_unspent_transactions(&address);
        for tx in unspent_txs {
            for out in tx.vout {
                if out.can_be_unlocked_with(address) {
                    outs.push(out)
                }
            }
        }
        outs
    }
    pub fn get_balance(self, address: &String) -> u64 {
        let mut balance = 0;
        let outs = self.find_outs(address);
        for out in outs {
            balance += out.value;
        }
        balance
    }
    pub fn new_utxo_transaction(&self, from: String, to: String, amount: u64) -> Result<Transaction, TransactionError> {
        let mut inputs: Vec<TXInput> = vec![];
        let mut outputs: Vec<TXOutput> = vec![];
        let (acc, valid_outs) = self.find_spendable_outs(&from, amount);

        if acc < amount {
            return Err(TransactionError::NotEnoughMoney);
        }

        for (tx_id_hex, outs) in valid_outs.iter() {
            let mut tx_id = Sha256Hash::default();

            tx_id.copy_from_slice(&tx_id_hex.from_hex().unwrap()[..]);
            for out in outs {
                let input = TXInput { tx_id: tx_id, vout: *out, script_sig: from.clone() };
                inputs.push(input);
            }
        }
        outputs.push(TXOutput { value: amount, script_pub_key: to.clone() });

        if acc > amount {
            outputs.push(TXOutput { value: acc - amount, script_pub_key: from.clone() });
        }

        Ok(Transaction::new(inputs, outputs))
    }
    fn find_spendable_outs(&self, from: &String, amount: u64) -> (u64, HashMap<String, Vec<i64>>) {
        let unspent_txs = self.find_unspent_transactions(from);
        let mut unspent_outs: HashMap<String, Vec<i64>> = HashMap::new();
        let mut acc = 0;

        'work: for tx in unspent_txs {
            let tx_id = tx.id.to_hex();
            for (id, out) in tx.vout.iter().enumerate() {
                if out.can_be_unlocked_with(from) {
                    acc += out.value;
                    match unspent_outs.get_mut(&tx_id) {
                        Some(vec) => vec.push(id as i64),
                        None => { unspent_outs.insert(tx_id.clone(), vec![id as i64]); }
                    }
                    if acc >= amount {
                        break 'work;
                    }
                }
            }
        }

        (acc, unspent_outs)
    }
    pub fn iter(&self) -> BlockchainIterator {
        self.into_iter()
    }
}


impl IntoIterator for Blockchain {
    type Item = Block;
    type IntoIter = BlockchainIterator;
    fn into_iter(self) -> Self::IntoIter {
        BlockchainIterator {
            store: Store::clone(&self.store),
            current_hash: self.tip.clone(),
        }
    }
}

impl IntoIterator for &Blockchain {
    type Item = Block;
    type IntoIter = BlockchainIterator;
    fn into_iter(self) -> Self::IntoIter {
        BlockchainIterator {
            store: Store::clone(&self.store),
            current_hash: self.tip.clone(),
        }
    }
}


pub struct BlockchainIterator {
    store: Store,
    current_hash: Option<Sha256Hash>,
}

impl Iterator for BlockchainIterator {
    type Item = Block;

    fn next(&mut self) -> Option<Block> {
        let rkv = self.store.rkv();
        let reader = rkv.read().unwrap();
        let single_store = self.store.single_store();

        match self.current_hash {
            Some(hash) => {
                match single_store.get(&reader, hash).unwrap() {
                    Some(l) => match l {
                        Value::Blob(val) => {
                            let block = Block::from_bytes(&val.to_vec()).unwrap();
                            self.current_hash = Some(block.prev_block_hash);
                            Some(block)
                        }
                        _ => panic!("Wrong format")
                    }
                    None => None
                }
            }
            None => None
        }
    }
}
