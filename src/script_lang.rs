use core::borrow::{Borrow, BorrowMut};
use std::error::Error;
use std::{error, fmt};

use crate::block::Sha256Hash;
use crate::wallet::{hash_pub_key, KeyHash, PubKeyBytes};

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

#[derive(Clone)]
enum StackValues {
    Value(u32),
    Signature(Sha256Hash),
    PubKeyHash(KeyHash),
    PubKey(PubKeyBytes),
}

enum ScriptToken {
    OpAdd,
    OpEqual,
    OpEqualVerify,
    OpCheckSig,
    OpHash160,
    OpDup,
    Value(StackValues),
}

struct ScriptSig {
    script: Vec<ScriptToken>,
}

impl ScriptSig {
    fn new() -> ScriptSig {
        ScriptSig { script: vec![] }
    }
    fn add(&mut self, value: ScriptToken) {
        self.script.push(value)
    }
    fn verify(&self) -> Result<bool, ScriptError> {
        let mut stack: Vec<StackValues> = vec![];
        let mut return_result = Err(ScriptError::WrongValue);
        for token in &self.script {
            match token {
                ScriptToken::Value(data) => stack.push(data.clone()),
                ScriptToken::OpDup => {
                    let value = stack.last().unwrap().clone();
                    stack.push(value)
                }
                ScriptToken::OpHash160 => {
                    let value = stack.pop().unwrap();
                    if let StackValues::PubKey(data) = value {
                        stack.push(StackValues::PubKeyHash(hash_pub_key(&data)));
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                ScriptToken::OpAdd => {
                    let first_value = stack.pop().unwrap();
                    let second_value = stack.pop().unwrap();
                    if let (StackValues::Value(value1), StackValues::Value(value2)) =
                        (first_value, second_value)
                    {
                        let result = value1 + value2;
                        stack.push(StackValues::Value(result));
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                ScriptToken::OpEqual => {
                    let first_value = stack.pop().unwrap();
                    let second_value = stack.pop().unwrap();
                    if let (StackValues::Value(value1), StackValues::Value(value2)) =
                        (first_value, second_value)
                    {
                        return_result = Ok(value1 == value2);
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                ScriptToken::OpEqualVerify => {
                    let first_value = stack.pop().unwrap();
                    let second_value = stack.pop().unwrap();
                    if let (StackValues::PubKeyHash(value1), StackValues::PubKeyHash(value2)) =
                        (first_value, second_value)
                    {
                        return_result = Ok(value1 == value2);
                    } else {
                        return_result = Err(ScriptError::WrongValue);
                    }
                }
                ScriptToken::OpCheckSig => {
                    let first_value = stack.pop().unwrap();
                    let second_value = stack.pop().unwrap();
                    if let (StackValues::PubKeyHash(value1), StackValues::Signature(value2)) =
                        (first_value, second_value)
                    {
                        return_result = Ok(true);
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

#[cfg(test)]
mod tests {
    use rustc_serialize::json::Stack;

    use crate::script_lang::{ScriptToken, StackValues};

    use super::ScriptSig;

    #[test]
    fn check_add() {
        let mut script = ScriptSig::new();
        script.add(ScriptToken::Value(StackValues::Value(1)));
        script.add(ScriptToken::Value(StackValues::Value(2)));
        script.add(ScriptToken::OpAdd);
        script.add(ScriptToken::Value(StackValues::Value(3)));
        script.add(ScriptToken::OpEqual);
        assert_eq!(script.verify().unwrap(), true)
    }
}
