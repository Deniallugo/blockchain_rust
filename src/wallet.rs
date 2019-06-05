extern crate rand;
extern crate secp256k1;
extern crate serde;
extern crate serde_big_array;

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use bincode::Error;
use bs58;
use crypto::digest::Digest as CryptoDigest;
use crypto::sha2::Sha256;
use rand::rngs::OsRng;
use ripemd160::{Digest, Ripemd160};
use rkv::Value;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::Secp256k1;
use serde::ser::Serialize;

use crate::block::Sha256Hash;
use crate::store::Store;

static VERSION: u8 = 0;

pub type KeyHash = [u8; 20];

pub type PubKeyBytes = [u8; 33];
pub type SecKeyBytes = [u8; 32];

big_array! {
    BigArray;
    33,
    64,
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    private_key: String,
    // TODO change to array
    #[serde(with = "BigArray")]
    pub public_key: PubKeyBytes,
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Address {}", self.get_address())
    }
}

impl Wallet {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();
        let (private_key, public_key) = secp.generate_keypair(&mut rng);
        Self {
            private_key: private_key.to_string(),
            public_key: public_key.serialize(),
        }
    }
    pub fn from_str(payload: String) -> Self {
        let secp = Secp256k1::new();
        const size_of_bytes: usize = 32;
        let mut payload_bytes: [u8; size_of_bytes] = Default::default();
        let mut payload_vec = payload.into_bytes();

        if payload_vec.len() < size_of_bytes {
            for _ in 0..(size_of_bytes - payload_vec.len()) {
                payload_vec.push(0);
            }
        } else {
            payload_vec = payload_vec[0..size_of_bytes].to_vec();
        }

        payload_bytes.copy_from_slice(&payload_vec);

        let private_key = SecretKey::from_slice(&payload_bytes).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        Self {
            private_key: private_key.to_string(),
            public_key: public_key.serialize(),
        }
    }

    pub fn get_address(&self) -> String {
        let mut payload: Vec<u8> = Default::default();
        let pub_hash_key = hash_pub_key(&self.public_key);
        payload.push(VERSION);
        payload.extend_from_slice(&pub_hash_key);
        let checksum = checksum(&payload);
        payload.extend_from_slice(&checksum);
        bs58::encode(payload).into_string()
    }

    pub fn private_key(&self) -> SecretKey {
        SecretKey::from_str(&self.private_key).unwrap()
    }
}

pub fn hash_pub_key(key: &PubKeyBytes) -> KeyHash {
    let mut hasher = Sha256::new();
    hasher.input(key);
    let mut hash = Sha256Hash::default();
    hasher.result(&mut hash);
    // hash to ripemd160
    let mut hasher = Ripemd160::new();
    hasher.input(hash);
    let mut hash = KeyHash::default();
    hash.copy_from_slice(hasher.result().as_slice());
    hash
}

fn checksum(payload: &Vec<u8>) -> [u8; 4] {
    let mut hasher = Sha256::new();

    let mut first_sha = Sha256Hash::default();
    hasher.input(payload);
    hasher.result(&mut first_sha);

    hasher.reset();

    hasher.input(&first_sha);
    let mut second_sha = Sha256Hash::default();
    hasher.result(&mut second_sha);
    let mut checksum_hash: [u8; 4] = Default::default();
    checksum_hash.copy_from_slice(&second_sha[0..4]);
    checksum_hash
}

pub fn address_to_pub_hash(address: String) -> KeyHash {
    let pub_key_hash = bs58::decode(&address.into_bytes()).into_vec().unwrap();
    let mut pub_key_bytes: KeyHash = [0; 20];
    pub_key_bytes.copy_from_slice(&pub_key_hash[1..pub_key_hash.len() - 4]);
    pub_key_bytes
}

#[derive(Serialize, Deserialize)]
pub struct Wallets {
    pub  wallets: HashMap<String, Wallet>,
}

impl Wallets {
    pub fn get(&self, key: &str) -> Option<&Wallet> {
        self.wallets.get(key)
    }
    pub fn new(path_str: String) -> Wallets {
        let store = Store::new(&path_str, "wallets".to_owned());
        let env = store.rkv();
        let single_store = store.single_store();
        let reader = env.read().unwrap();
        let wallets = match single_store.get(&reader, "wallets") {
            Ok(l_opt) => match l_opt {
                Some(l) => {
                    if let Value::Blob(val) = l {
                        Wallets::from_bytes(&val.to_vec()).unwrap()
                    } else {
                        panic!("Wrong format")
                    }
                }
                None => Self {
                    wallets: Default::default(),
                }
            }
            Err(e) => {
                panic!("{}", e);
            }
        };
        wallets
    }
    pub fn save_to_file(&self, path_str: String) {
        let store = Store::new(&path_str, "wallets".to_owned());
        let env = store.rkv();
        let single_store = store.single_store();
        let mut writer = env.write().unwrap();
        single_store.put(&mut writer, "wallets", &Value::Blob(&self.serialize())).unwrap();
        writer.commit().unwrap()
    }
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self, Error> {
        bincode::deserialize(bytes)
    }
    pub fn create_wallet(&mut self) -> &Wallet {
        let wallet = Wallet::new();
        let address = wallet.get_address();
        self.wallets.insert(address.clone(), wallet);
        self.save_to_file("wallets".to_string());
        self.wallets.get(&address).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::Wallets;

    use super::Wallet;

    #[test]
    fn get_address() {
        let wallet = Wallet::new();
        let address: String = wallet.get_address();
        assert_eq!(address.len(), 34)
    }

    #[test]
    fn get_address_from_small_payload() {
        let test_payload = "test".to_string();
        let first_wallet = Wallet::from_str(test_payload);
        let test_payload = "test".to_string();
        let second_wallet = Wallet::from_str(test_payload);
        assert_eq!(first_wallet.get_address(), second_wallet.get_address())
    }

    #[test]
    fn get_address_from_big_payload() {
        let test_payload = "1".to_string().repeat(32);
        let first_wallet = Wallet::from_str(test_payload);
        let mut test_payload = "1".to_string().repeat(32);
        test_payload.push('1');
        let second_wallet = Wallet::from_str(test_payload);
        assert_eq!(first_wallet.get_address(), second_wallet.get_address())
    }

    #[test]
    fn wallets_create() {
        let mut wallets = Wallets::new("wallets".to_string());
        let wallet = wallets.create_wallet();
        wallets.save_to_file("wallets".to_string());
        let from_wallets = Wallets::new("wallets".to_string());
        let a = wallets.wallets.len();
        assert_eq!(wallets.wallets.len(), from_wallets.wallets.len());
        assert_ne!(wallets.wallets.len(), 0);
        println!("{}", wallets.wallets.len())
    }
}