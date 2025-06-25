extern crate core;

mod files;
mod console;
mod crypto;

use std::{env};
use std::error::Error;
use bip39::Mnemonic;
use crate::console::{extract_parameter_and_value, print_help};
use crate::crypto::{check_first_arg, generate_entropy};
use crate::files::{check_files, WalletInfo};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = env::args().map(|s| s.trim().to_string()).collect();

    let wallets: Vec<WalletInfo> = check_files(&args)?;

    println!("List of wallets: ");
    println!();

    for (ind, init) in wallets.iter().enumerate() {
        println!("{} - {} - {}", ind, init.name, init.size);
    }

    println!();


    if check_first_arg(&args) {
        return Ok(());
    }

    let mut count = 10_u16;
    let mut from = 0_u16;
    let mut id: Option<usize> = None;
    let mut wid: Option<usize> = None;

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return Ok(());
    }

    if let Some((arg, value)) = extract_parameter_and_value(&mut args, "-c", "--count", true) {
        if let Some(value) = value {
            count = value.parse()?;
            println!("count = {}", count);
        } else {
            return Err(format!("Wrong argument {}", arg).into());
        }
    }

    if let Some((arg, value)) = extract_parameter_and_value(&mut args, "-f", "--from", true) {
        if let Some(value) = value {
            from = value.parse()?;
            println!("from = {}", from);
        } else {
            return Err(format!("Wrong argument {}", arg).into());
        }
    }

    if let Some((arg, value)) = extract_parameter_and_value(&mut args, "-i", "--key_id", true) {
        if let Some(value) = value {
            let key_id = value.parse()?;
            id = Some(key_id);
            println!("key_id = {}", key_id);
        } else {
            return Err(format!("Wrong argument {}", arg).into());
        }
    }

    if let Some((arg, value)) = extract_parameter_and_value(&mut args, "-w", "--wallet_id", true) {
        if let Some(value) = value {
            let wallet_id = value.parse()?;
            wid = Some(wallet_id);

            if wallets.get(wallet_id) == None {
                return Err(format!("Wrong wallet id {}", wallet_id).into());
            }

            println!("wallet_id = {}", wallet_id);
        } else {
            return Err(format!("Wrong argument {}", arg).into());
        }
    }

    println!();

    if args.len() < 2 {
        print_help();
        return Ok(());
    }

    args[0] = "bip39gen.exe".to_string();
    args.push("YGsgGNfhgKYFGSknuyfgSNdyifrsd8bf5rUB6f5rU^VFRS^Df".to_string());

    let pass: String = args.join("_");
    let entropy = generate_entropy(&pass, false, 9_000_000, Some(500_000));
    let mnemonic_init = Mnemonic::from_entropy(&entropy).unwrap().to_string();

    println!();

    for (wallet_id, item) in wallets.iter().enumerate() {
        if wid != None && wid != Some(wallet_id) {
            continue;
        }

        println!("{}:", item.full_name);

        let to = from + count;
        let fx: usize = from as usize;
        let tx: usize = to as usize;

        let mut current_count: u16 = 0;

        'wallet_roll: for current_id in 1..=to {
            let new_pass: String = format!("{}-{}-{}", mnemonic_init, item.name, current_id);
            let entropy_size = if item.size == 12 { 16 } else { 32 };
            let new_entropy = &generate_entropy(&new_pass, false, 1000, None)[0..entropy_size];
            let new_mnemonic = Mnemonic::from_entropy(new_entropy).unwrap().to_string();

            let index: usize = (current_id - 1) as usize;

            if index >= fx && index <= tx {
                current_count += 1;

                if id == None || Some(index) == id {
                    println!(" {}: {}", index, new_mnemonic);
                }

                if current_count >= count {
                    break 'wallet_roll;
                }
            }
        }
    }

    return Ok(());
}
