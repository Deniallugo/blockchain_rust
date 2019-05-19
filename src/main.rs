extern crate structopt;

use structopt::StructOpt;

use blockchain::blockchain::Blockchain;

#[derive(StructOpt)]
struct Cli {
    command: String,
    #[structopt(default_value = "test")]
    from: String,
    #[structopt(default_value = "test")]
    to: String,
    #[structopt(default_value = "0")]
    amount: u64,
}

fn main() {
    let mut bc = match Blockchain::new("block".to_owned(), "Ivan".to_string()) {
        Ok(ch) => ch,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
    let args = Cli::from_args();
    match args.command.as_ref() {
        "send" => {
            let tx = bc.new_utxo_transaction(args.from, args.to, args.amount).unwrap();
            match bc.mine_block(vec![tx]) {
                Ok(_) => println!("Block successfully add"),
                Err(e) => println!("{}", e)
            }
        }
        "printchain" => {
            for block in bc {
                println!("{}", block);
            }
        }
        "get_balance" => {
            println!("Balance of {} is {}", &args.from, bc.get_balance(&args.from));
        }

        _ => panic!("Wrong command")
    }
}
