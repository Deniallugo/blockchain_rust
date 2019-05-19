use rkv::Value;

use crate::block::{Block, Sha256Hash};
use crate::mining_error::MiningError;
use crate::store::Store;

pub struct Blockchain {
    tip: Option<Sha256Hash>,
    path: String,
    store: Store,
}

impl Blockchain {
    pub fn new(path_str: String) -> Result<Blockchain, MiningError> {
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
                    gen_block = Block::genesis_block()?;
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
    pub fn add_block(&mut self, data: String) -> Result<(), MiningError> {
        let mut block: Block;

        let rkv = self.store.rkv();
        let single_store = self.store.single_store();

        match self.tip {
            Some(hash) => {
                block = Block::new(data, hash)?;
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
