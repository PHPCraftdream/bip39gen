use std::env;

pub fn extract_parameter_and_value(args: &mut Vec<String>, short_param: &str, long_param: &str, use_value: bool) -> Option<(String, Option<String>)> {
    let mut i = 0;
    let short_param = short_param.to_lowercase();
    let long_param = long_param.to_lowercase();

    while i < args.len() {
        let arg = &args[i].to_lowercase();

        if arg == short_param.as_str() || arg == long_param.as_str() {
            args.remove(i);

            if !use_value {
                return Some((arg.clone(), None));
            }

            if i < args.len() {
                let value = args.remove(i);
                return Some((arg.clone(), Some(value)));
            }

            return Some((arg.clone(), None));
        }
        i += 1;
    }
    None
}

pub fn print_help () {
    println!("-h\t--help\t\t--> Print this help");
    println!("-c\t--count\t\t--> Count of keys to generate");
    println!("-f\t--from\t\t--> The index from which the keys will be generated");
    println!("-i\t--key_id\t--> Print key only with that id [from 0]");
    println!("-w\t--wallet_id\t--> Print wallet only with that id [from 0], see -l, --list");

    let exe_path = env::current_exe().unwrap();
    let exe_name = exe_path.file_name().unwrap().to_str().unwrap();

    println!();
    println!("Examples:");
    println!();

    println!("Just generate 10 keys for each wallets:");
    println!("\t{} seed phrase to generate keys", exe_name);
    println!();

    println!("Just generate 5 keys for each wallets:");
    println!("\t{} -c 5 seed phrase to generate keys", exe_name);
    println!("\t{} --count 5 seed phrase to generate keys", exe_name);
    println!();

    println!("Just generate keys with id=2:");
    println!("\t{} -i 2 seed phrase to generate keys", exe_name);
    println!("\t{} --id 2 seed phrase to generate keys", exe_name);
    println!();

    println!("Just generate keys with id=2 in wallet with id=3:");
    println!("\t{} -i 2 -w 3 seed phrase to generate keys", exe_name);
    println!("\t{} --id 2 --wallet_id 3 seed phrase to generate keys", exe_name);
    println!();
}
