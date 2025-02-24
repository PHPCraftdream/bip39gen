use std::error::Error;
use std::path::PathBuf;
use std::fs;
use sha2::{Digest as DigestSha256, Sha256};
use num_format::Locale;
use num_format::ToFormattedString;
use md5::{Md5};

pub fn lf(base: &str, filename: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = PathBuf::from(base).join(filename);
    let data = fs::read(path)?;

    Ok(data)
}

pub fn wf(base: &str, filename: &str, content: &str) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(base).join(filename);
    fs::write(path, content)?;
    Ok(())
}

pub fn check_files(args: &Vec<String>) -> Result<Vec<String>, Box<dyn Error>> {
    let current_file_data = lf("./", &args[0]);

    if let Err(_) = current_file_data {
        return Err(format!("Error on read file - {}", args[0]).into());
    }

    if let Ok(file_data) = current_file_data {
        let mut hasher_sha256 = Sha256::new();
        hasher_sha256.update(&file_data);
        let res: String = hasher_sha256.finalize_reset().to_vec().iter().map(|byte| format!("{:02x}", byte)).collect();
        println!("sha256: {:?}", res);

        let mut hasher_md5 = Md5::new();
        hasher_md5.update(&file_data);
        let result = hasher_md5.finalize();
        let res: String = result.iter().map(|byte| format!("{:02x}", byte)).collect();
        println!("md5: {:?}", res);

        println!("size: {}", file_data.len().to_formatted_string(&Locale::en));

        println!();

        println!("source: https://github.com/PHPCraftdream/bip39gen");
        println!("release: https://github.com/PHPCraftdream/bip39gen/releases/tag/0.0.1");
        println!("learn: https://t.me/Crypto_znanie_bot");

        println!();
    }

    let cm_file = lf("./", "cm.bat");

    if let Err(_) = cm_file {
        wf("./", "cm.bat", "cmd")?;
    }

    if let Ok(cm_data) = cm_file {
        let cm_str: String = String::from_utf8(cm_data)?;

        if cm_str != "cmd" {
            wf("./", "cm.bat", "cmd")?;
        }
    }

    let w_file = lf("./", "wallets.txt");

    if let Err(_) = w_file {
        let wallets: Vec<String> = vec![
            "Electrum".to_string(),
            "Ethereum-MyCrypto".to_string(),
            "Solana-Exodus".to_string(),
            "Sui-Atomic".to_string(),
            "Avax-Exodus".to_string(),
            "Doge-Exodus".to_string(),
            "Pepe-Exodus".to_string(),
            "ShibaInu-Exodus".to_string(),
        ];

        wf("./", "wallets.txt", &wallets.join("\n"))?;

        return Ok(wallets);
    }

    if let Ok(wallet_bytes) = w_file {
        let lines: Vec<String> = wallet_bytes
            .split(|&b| b == b'\n') // Разбиваем на строки по символу '\n'
            .map(|line| String::from_utf8(line.to_vec())) // Преобразуем каждую строку в String
            .filter_map(Result::ok) // Фильтруем успешные преобразования
            .map(|line| line.trim().to_string())
            .filter(|line| line.len() > 0)
            .collect();

        return Ok(lines);
    }

    return Err("Unknown error".into());
}
