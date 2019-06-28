use std::cell::RefCell;
use std::collections::HashMap;

use rkv::Value;
use rkv::value::Type::Str;
use rustc_serialize::hex::{FromHex, ToHex};
use secp256k1::SecretKey;

use crate::block::{Block, Sha256Hash};
use crate::mining_error::MiningError;
use crate::script_lang::ScriptSig;
use crate::store::Store;
use crate::transaction::{Transaction, TransactionError, TXInput, TXOutput};
use crate::wallet::{address_to_pub_hash, hash_pub_key, KeyHash, Wallet, Wallets};

pub struct Blockchain {
    tip: Option<Sha256Hash>,
    path: String,
    pub(crate) store: Store,
}

impl Blockchain {
    pub fn new(
        path_str: String,
        mut wallets: &mut Wallets,
    ) -> Result<(Blockchain, Option<String>), MiningError> {
        let store = Store::new(&path_str, "block".to_owned());
        let env = store.rkv();
        let single_store = store.single_store();
        let reader = env.read().unwrap();
        let mut address: Option<String> = None;
        let mut gen_block;
        let tip = match single_store.get(&reader, "l") {
            Ok(l_opt) => match l_opt {
                Some(l) => {
                    if let Value::Blob(val) = l {
                        let mut a: [u8; 32] = Default::default();
                        a.copy_from_slice(val);
                        a
                    } else {
                        panic!("Wrong format")
                    }
                }
                None => {
                    let mut wallet = wallets.create_wallet();
                    let wallet_address = wallet.get_address();
                    let coinbase_transaction =
                        Transaction::new_coinbase_tx(&wallet_address, "genesis block".to_string());
                    gen_block = Block::genesis_block(coinbase_transaction)?;
                    address = Some(wallet_address);
                    let mut writer = env.write().unwrap();
                    single_store
                        .put(
                            &mut writer,
                            &gen_block.hash,
                            &Value::Blob(&gen_block.serialize()),
                        )
                        .unwrap();
                    single_store
                        .put(&mut writer, "l", &Value::Blob(&gen_block.hash))
                        .unwrap();
                    writer.commit().unwrap();
                    gen_block.hash
                }
            },
            Err(e) => {
                panic!("{}", e);
            }
        };
        Ok((
            Blockchain {
                store: Store::clone(&store),
                path: path_str,
                tip: Some(tip),
            },
            address,
        ))
    }

    pub fn verify_transaction(&self, tx: &Transaction) -> bool {
        if tx.is_coinbase() {
            return true;
        }
        let mut prev_txs: HashMap<String, Transaction> = Default::default();
        for vin in tx.vin.iter() {
            let borrow_vin = vin.borrow();
            prev_txs.insert(
                borrow_vin.tx_id.to_hex(),
                self.find_transaction(&borrow_vin.tx_id),
            );
        }
        tx.verify(prev_txs)
    }
    pub fn find_transaction(&self, tx_id: &Sha256Hash) -> Transaction {
        for block in self.iter() {
            for tx in block.transactions {
                if tx.id == *tx_id {
                    return tx.clone();
                }
            }
        }
        panic!("No transacton for id {}", tx_id.to_hex())
    }
    pub fn mine_block(&mut self, transactions: Vec<Transaction>) -> Result<(), MiningError> {
        let mut block: Block;

        let rkv = self.store.rkv();
        let single_store = self.store.single_store();

        for tx in transactions.iter() {
            if !self.verify_transaction(tx) {
                panic!("Failed transaction")
            }
        }

        match self.tip {
            Some(hash) => {
                block = Block::new(transactions, hash)?;
                let mut writer = rkv.write().unwrap();
                single_store
                    .put(&mut writer, &block.hash, &Value::Blob(&block.serialize()))
                    .unwrap();
                single_store
                    .put(&mut writer, "l", &Value::Blob(&block.hash))
                    .unwrap();
                writer.commit().unwrap();
            }
            None => {
                return Err(MiningError::NoParent);
            }
        }
        self.tip = Some(block.hash);
        Ok(())
    }
    pub fn find_unspent_transactions(&self, pub_key_hash: &KeyHash) -> Vec<Transaction> {
        let mut unspent_txs: Vec<Transaction> = vec![];
        let mut spent_txs: HashMap<String, Vec<i64>> = HashMap::new();
        for block in self.iter() {
            for tx in block.transactions {
                let tx_id = tx.id.to_hex();
                'outs: for (out_idx, out) in tx.vout.iter().enumerate() {
                    match spent_txs.get(&tx_id) {
                        Some(spent_outs) => {
                            for val in spent_outs {
                                if *val == out_idx as i64 {
                                    continue 'outs;
                                }
                            }
                        }
                        None => (),
                    }

                    if out.is_locker_with_key(pub_key_hash) {
                        unspent_txs.push(tx.clone()) // Ask about it, can i save it better?
                    }
                    if !tx.is_coinbase() {
                        for vin in &tx.vin {
                            let ref_vin = vin.borrow();
                            if ref_vin.uses_key(pub_key_hash) {
                                let in_tx_id = ref_vin.tx_id.to_hex();

                                match spent_txs.get_mut(&in_tx_id) {
                                    Some(vec) => vec.push(ref_vin.vout),
                                    None => {
                                        spent_txs.insert(in_tx_id, vec![ref_vin.vout]);
                                    }
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
    pub fn find_outs(self, pub_key_hash: &KeyHash) -> Vec<TXOutput> {
        let mut outs: Vec<TXOutput> = vec![];
        let unspent_txs = self.find_unspent_transactions(pub_key_hash);
        for tx in unspent_txs {
            for out in tx.vout {
                if out.is_locker_with_key(pub_key_hash) {
                    outs.push(out)
                }
            }
        }
        outs
    }
    pub fn get_balance(self, address: &String) -> u64 {
        let pub_key_hash = &address_to_pub_hash(address);
        let mut balance = 0;
        let outs = self.find_outs(&pub_key_hash);
        for out in outs {
            balance += out.value;
        }
        balance
    }
    pub fn new_utxo_transaction(
        &self,
        from: &Wallet,
        to: String,
        amount: u64,
    ) -> Result<Transaction, TransactionError> {
        let mut inputs: Vec<RefCell<TXInput>> = vec![];
        let mut outputs: Vec<TXOutput> = vec![];
        let (acc, valid_outs) = self.find_spendable_outs(from.clone(), amount);
        if acc < amount {
            return Err(TransactionError::NotEnoughMoney);
        }

        for (tx_id_hex, outs) in valid_outs.iter() {
            let mut tx_id = Sha256Hash::default();

            tx_id.copy_from_slice(&tx_id_hex.from_hex().unwrap()[..]);

            for out in outs {
                let input = TXInput {
                    tx_id,
                    vout: *out,
                    script_sig: ScriptSig {
                        pub_key: from.public_key.clone(),
                        signature: [0; 64],
                    },
                };
                inputs.push(RefCell::new(input));
            }
        }
        outputs.push(TXOutput::new(amount, &to));

        if acc > amount {
            outputs.push(TXOutput::new(amount, &from.get_address()));
        }
        let mut tx = Transaction::new(inputs, outputs);
        Ok(self.sign_transaction(&tx, &from.private_key()))
    }
    fn sign_transaction(&self, tx: &Transaction, priv_key: &SecretKey) -> Transaction {
        let mut prev_txs: HashMap<String, Transaction> = Default::default();
        for vin in tx.vin.iter() {
            let borrow_vin = vin.borrow();
            prev_txs.insert(
                borrow_vin.tx_id.to_hex(),
                self.find_transaction(&borrow_vin.tx_id),
            );
        }
        tx.sign(priv_key, prev_txs).unwrap()
    }
    fn find_spendable_outs(&self, from: &Wallet, amount: u64) -> (u64, HashMap<String, Vec<i64>>) {
        let pub_key_hash = hash_pub_key(&from.public_key);
        let unspent_txs = self.find_unspent_transactions(&pub_key_hash);
        let mut unspent_outs: HashMap<String, Vec<i64>> = HashMap::new();
        let mut acc = 0;

        'work: for tx in unspent_txs {
            let tx_id = tx.id.to_hex();
            for (id, out) in tx.vout.iter().enumerate() {
                if out.is_locker_with_key(&pub_key_hash) {
                    acc += out.value;
                    match unspent_outs.get_mut(&tx_id) {
                        Some(vec) => vec.push(id as i64),
                        None => {
                            unspent_outs.insert(tx_id.clone(), vec![id as i64]);
                        }
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
        if let Some(ref hash) = self.current_hash {
            match single_store.get(&reader, hash).unwrap() {
                None => None,
                Some(l) => {
                    if let Value::Blob(val) = l {
                        let block = Block::from_bytes(&val.to_vec()).unwrap();
                        self.current_hash = Some(block.prev_block_hash);
                        Some(block)
                    } else {
                        panic!("Wrong format")
                    }
                }
            }
        } else {
            None
        }
    }
}
