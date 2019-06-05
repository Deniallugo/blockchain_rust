extern crate serde;
#[macro_use]
extern crate serde_big_array;
#[macro_use]
extern crate serde_derive;

pub mod blockchain;
pub mod wallet;
mod block;
mod mining_error;
mod proof_of_work;
mod store;
mod utxo;
pub mod transaction;
