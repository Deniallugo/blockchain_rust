extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod blockchain;
mod block;
mod mining_error;
mod proof_of_work;
mod store;
mod transaction;
