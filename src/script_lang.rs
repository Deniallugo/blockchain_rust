extern crate serde;
extern crate serde_big_array;

use core::borrow::{Borrow, BorrowMut};
use std::{error, fmt};
use std::error::Error;

use secp256k1::{Message, PublicKey, Secp256k1, Signature, Verification};

use crate::block::Sha256Hash;
use crate::wallet::{hash_pub_key, KeyHash, PubKeyBytes};

big_array! {
    BigArray;
    33,
    64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ScriptSig {
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    #[serde(with = "BigArray")]
    pub pub_key: PubKeyBytes,
}

#[derive(Debug)]
pub enum ScriptError {
    WrongValue,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ScriptError::WrongValue => write!(f, "Wrong value"),
        }
    }
}

impl error::Error for ScriptError {
    fn description(&self) -> &str {
        match *self {
            ScriptError::WrongValue => "Wrong value",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum StackValues {
    Value(u32),
    #[serde(with = "BigArray")]
    Signature([u8; 64]),
    PubKeyHash(KeyHash),
    #[serde(with = "BigArray")]
    PubKey(PubKeyBytes),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ScriptToken {
    OpAdd,
    OpEqual,
    OpEqualVerify,
    OpCheckSig,
    OpHash160,
    OpDup,
    Value(StackValues),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ScriptPubKey {
    pub script: Vec<ScriptToken>,
}

impl ScriptPubKey {
    fn new() -> ScriptPubKey {
        ScriptPubKey { script: vec![] }
    }
    fn add(&mut self, value: ScriptToken) {
        self.script.push(value)
    }
    fn verify(
        &self,
        script_sig: Option<ScriptSig>,
        tx_in_hash: Option<Sha256Hash>,
    ) -> Result<bool, ScriptError> {
        use ScriptToken::*;
        let mut stack: Vec<StackValues>;
        if let Some(sig) = script_sig {
            stack = vec![
                StackValues::Signature(sig.signature),
                StackValues::PubKey(sig.pub_key),
            ];
        } else {
            stack = vec![]
        }

        let mut return_result = Err(ScriptError::WrongValue);
        for token in &self.script {
            match token {
                Value(data) => stack.push(data.clone()),
                OpDup => {
                    if let Some(value) = stack.last() {
                        stack.push(value.clone())
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                OpHash160 => {
                    let value = stack.pop();
                    if let Some(StackValues::PubKey(data)) = value {
                        stack.push(StackValues::PubKeyHash(hash_pub_key(&data)));
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                OpAdd => {
                    let first_value = stack.pop();
                    let second_value = stack.pop();
                    if let (Some(StackValues::Value(value1)), Some(StackValues::Value(value2))) =
                    (first_value, second_value)
                    {
                        let result = value1 + value2;
                        stack.push(StackValues::Value(result));
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                OpEqual => {
                    let first_value = stack.pop();
                    let second_value = stack.pop();
                    if let (Some(StackValues::Value(value1)), Some(StackValues::Value(value2))) =
                    (first_value, second_value)
                    {
                        return_result = Ok(value1 == value2);
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                OpEqualVerify => {
                    let first_value = stack.pop();
                    let second_value = stack.pop();
                    if let (
                        Some(StackValues::PubKeyHash(value1)),
                        Some(StackValues::PubKeyHash(value2)),
                    ) = (first_value, second_value)
                    {
                        return_result = Ok(value1 == value2);
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                OpCheckSig => {
                    let first_value = stack.pop();
                    let second_value = stack.pop();
                    if let (
                        Some(StackValues::PubKey(pub_key)),
                        Some(StackValues::Signature(sign)),
                    ) = (first_value, second_value)
                    {
                        if let Some(tx_hash) = tx_in_hash {
                            return_result = Ok(verify(&tx_hash, &pub_key, &sign))
                        } else {
                            return_result = Err(ScriptError::WrongValue);
                        }
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
            }
        }
        if stack.is_empty() {
            return return_result;
        } else {
            return Err(ScriptError::WrongValue);
        }
    }
}

fn verify(msg: &Sha256Hash, key: &PubKeyBytes, signature: &[u8; 64]) -> bool {
    let verificator = Secp256k1::verification_only();
    verificator
        .verify(
            &Message::from_slice(msg).unwrap(),
            &Signature::from_compact(signature).unwrap(),
            &PublicKey::from_slice(key).unwrap(),
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use rustc_serialize::json::Stack;
    use secp256k1::Secp256k1;
    use secp256k1::VerifyOnly;

    use crate::script_lang::{ScriptToken, StackValues};

    use super::ScriptPubKey;

    #[test]
    fn check_add() {
        use ScriptToken::*;
        let mut script = ScriptPubKey::new();
        script.add(Value(StackValues::Value(1)));
        script.add(Value(StackValues::Value(2)));
        script.add(OpAdd);
        script.add(Value(StackValues::Value(3)));
        script.add(OpEqual);
        assert_eq!(script.verify(None, None).unwrap(), true)
    }

    fn verify() {}
}
