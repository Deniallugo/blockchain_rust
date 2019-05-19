extern crate structopt;

use structopt::StructOpt;

use blockchain::blockchain::Blockchain;

#[derive(StructOpt)]
struct Cli {
    command: String,
    #[structopt(default_value = "test")]
    value: String,
}

fn main() {
    let mut bc = match Blockchain::new("block".to_owned()) {
        Ok(ch) => ch,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
    let args = Cli::from_args();
    match args.command.as_ref() {
        "add_block" => {
            match bc.add_block(args.value) {
                Ok(_) => println!("Block successfully add"),
                Err(e) => println!("{}", e)
            }
        }
        "printchain" => {
            for block in bc {
                println!("{}", block);
            }
        }
        _ => panic!("Wrong command")
    }
}

//fn main() {
//    let mut bc = match Blockchain::new("block".to_owned()) {
//        Ok(ch) => ch,
//        Err(e) => {
//            println!("{:?}", e);
//            return;
//        }
//    };
//
//}
//

//use rkv::{Manager, StoreOptions, Rkv, Value};
//use std::fs;
//use std::path::Path;
//
//fn main() {
//    let path = Path::new("block");
//
//    fs::create_dir_all(path).unwrap();
//
//    let created_arc = Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap();
//    let env = created_arc.read().unwrap();
//    let store = env.open_single("store", StoreOptions::create()).unwrap();
//
//    let mut writer = env.write().unwrap();
//    let mut reader = env.read().unwrap();
//    store.get(&reader, "l").unwrap();
//
//}
