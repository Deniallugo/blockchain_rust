extern crate structopt;



use structopt::StructOpt;

use blockchain::blockchain::Blockchain;
use blockchain::transaction::Transaction;
use blockchain::wallet::{Wallets};

#[derive(StructOpt)]
struct Send {
    #[structopt(default_value = "test")]
    from: String,
    #[structopt(default_value = "test")]
    to: String,
    #[structopt(default_value = "0")]
    amount: u64,
}

#[derive(StructOpt)]
enum Cli {
    #[structopt(name = "send")]
    Send(Send),
    #[structopt(name = "coinbase")]
    Coinbase { to: String },
    #[structopt(name = "balance")]
    Balance { of: String },
    #[structopt(name = "address")]
    Address,
    #[structopt(name = "printchain")]
    Print,
}

fn main() {
    let mut wallets = Wallets::new("wallets".to_owned());

    let mut bc = match Blockchain::new("block".to_owned(), &mut wallets) {
        Ok((blockchain, address)) => {
            if let Some(new_address) = address {
                println!("Blockchain was created for {}", new_address)
            };
            blockchain
        }
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
    match Cli::from_args() {
        Cli::Send(cmd) => {
            let wallet = match wallets.get(&cmd.from) {
                Some(t) => t,
                None => panic!("Wallet not find"),
            };
            let tx = bc.new_utxo_transaction(wallet, cmd.to, cmd.amount).unwrap();
            match bc.mine_block(vec![tx]) {
                Ok(_) => println!("Block successfully add"),
                Err(e) => println!("{}", e),
            }
        }
        Cli::Coinbase { to } => {
            if wallets.get(&to).is_none() {
                panic!("Wallet not found")
            }

            let tx = Transaction::new_coinbase_tx(&to, "".to_string());
            match bc.mine_block(vec![tx]) {
                Ok(_) => println!("Block successfully add"),
                Err(e) => println!("{}", e),
            }
        }
        Cli::Print => {
            for block in bc {
                println!("{}", block);
            }
        }
        Cli::Balance { of } => {
            println!("Balance of {} is {}", &of, bc.get_balance(&of));
        }
        Cli::Address => {
            let wallet = wallets.create_wallet();
            println!("New address {}", wallet.get_address());
        }
    }
}
