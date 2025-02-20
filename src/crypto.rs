#![allow(dead_code)]

use sha2::{Digest, Sha256};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine};

pub fn generate_entropy(pass: &str, itr_count: u32) -> Vec<u8> {
    let base_s = "SHALOM-WORLD";
    let base_str = "".to_string() + &base_s + pass + &base_s;
    let base_b = base_str.as_bytes();
    let mut entropy = base_b.to_vec();

    let mut hash = Sha256::new();
    hash.update(&entropy);
    entropy = hash.finalize_reset().to_vec();

    let add_itr: u32 = entropy.iter().map(|&x| x as u32).sum();
    let itr: u32 = itr_count + add_itr;
    let mut last_progress: f64 = -1.0;
    let show_debug = itr_count > 100_000;

    if show_debug {
        println!("total: {}", itr);
    }

    for i in 0..itr {
        hash.update(&entropy);
        hash.update(&base_b);
        hash.update((itr + i).to_be_bytes());
        hash.update(&entropy);
        hash.update(&base_b);
        hash.update(&entropy);

        entropy = hash.finalize_reset().to_vec();

        if show_debug && i % 1000000 == 0 {
            let current_progress: f64 = (100_f64 * i as f64 / itr as f64).round();

            if current_progress != last_progress {
                last_progress = current_progress;

                println!("progress: {}%", 100 * i / itr);
            }
        }
    }

    entropy
}

fn encrypt_once(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Неверная длина ключа, требуется 32 байта");
    let nonce = Nonce::from_slice(iv);
    cipher.encrypt(nonce, plaintext)
        .expect("Ошибка шифрования")
}

fn decrypt_once(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Неверная длина ключа, требуется 32 байта");
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, ciphertext)
        .expect("Ошибка расшифрования")
}

fn encrypt_n(plaintext: &str, key: &[u8], iv: &[u8], rounds: usize) -> Vec<u8> {
    let mut data = plaintext.as_bytes().to_vec();
    for _ in 0..rounds {
        data = encrypt_once(&data, key, iv);
    }
    data
}

fn decrypt_n(ciphertext: &[u8], key: &[u8], iv: &[u8], rounds: usize) -> String {
    let mut data = ciphertext.to_vec();
    for _ in 0..rounds {
        data = decrypt_once(&data, key, iv);
    }
    String::from_utf8(data).expect("Ошибка преобразования байтов в строку")
}

pub fn vec_to_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn base64_to_vec(encoded: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(encoded).expect("Ошибка декодирования base64")
}

pub fn encrypt_s(plaintext: &str, password: &str) -> String {
    let key = generate_entropy(password, 10);
    let iv = generate_entropy(password, 12)[0..12].to_vec();

    let encrypted = encrypt_n(plaintext, &key, &iv, 10);

    vec_to_base64(&encrypted)
}

pub fn decrypt_s(plaintext: &str, password: &str) -> String {
    let bytes: Vec<u8> = base64_to_vec(plaintext);

    let key = generate_entropy(password, 10);
    let iv = generate_entropy(password, 12)[0..12].to_vec();

    let decrypted = decrypt_n(&bytes, &key, &iv, 10);

    decrypted
}

pub fn ent_str(str: &str, itr_count: u32) -> String {
    let arg_e = generate_entropy(str, itr_count);

    vec_to_base64(&arg_e)
}

pub fn check_first_arg(args: &Vec<String>) -> bool {
    if let Some(arg) = args.get(1) {
        if arg.starts_with("**") || arg.starts_with("--") {
            let arg_name: String = arg.chars().skip(2).collect();
            let arg_d = arg_name.clone() + &arg_name;

            let arg_hash_1 = ent_str(&arg_name, 100000);
            let arg_hash_2 = ent_str(&arg_d, 100000);

            let ok_1 = arg_hash_1 == "uEcTZmXHcQTV7HgZLLS8qhO+1la6cT7/fx5eBlAo0H8=";
            let ok_2 = arg_hash_2 == "ehBbprT9rOsFuPF9J4ABf2xl7oycUEBOdzYHAScSyfw=";

            if ok_1 && ok_2 {
                let key = generate_entropy(&arg_name, 60000);
                let key_e64 = vec_to_base64(&key);

                let items = vec![
                    "ZGFyaW5nIHJhY2Ugc3VyZmFjZSBzY3J1YiBoYXBweSBzcHJheSBmaXggc2VsbCBmYW1vdXMgZGVtaXNlIGJsYWNrIG11c2ljmC3bTA3jw2h+zmT+5T51ACK9YJClygb283xkUUqDdZLZ2aO9kvDXMju2FeHDqO5bTz4MXHCtaLPxaufA9eqr0+TZ5s8Cle66HypVzRGlwyOpmUdCqGz5jA7caRNllXpLtOrLqhV9vT0+ou/iAs/OkbH9LAVWsTvm90dt3Wl/yq3TEK/l8BeyQmXcHy6tkUEBYFKWtd40VmMMJqywTfGRrg==",
                    "YnJhdmUgcmVjaXBlIHNjb3JwaW9uIGVycm9yIHRocm93IHdyZXN0bGUgZ2VuaXVzIG9mdGVuIGhhemFyZCBvYmxpZ2UgYW5ncnkgdmludGFnZazBFxFs/DZRV/rXmqA3RVF2HpFlIbzsAjacTW1nr3CazQWXWpAksMLPfZXE4IDiZd2LrAK2zbFBeBbgUuSDggXSEUUjcxmMXVQIzeOEBJ327Cpdu3EKkIyEJzCHUEFMeUDCJomzT/WvRgO7qStUJWhmWIvMmiAwmQwATiDaShKKXkm1wcYPzaDous/Q9GbnSScN/N0IEB61AlAYRHtfodQ=",
                    "bXVzdCBhbWF0ZXVyIHVzZWxlc3MgbWlycm9yIGFjb3VzdGljIGFlcm9iaWMgc291bCBvY2N1ciBzdHVkZW50IGV4ZWN1dGUgcmFuZ2UgbGlmdE48vg2ZRNwUBYFtGY+syuGFTu18XkDf7voXDr4idgrxpM3kH9WJFzmk02IjGtYmtB6hStfBavYSdWm/79qfnWNZdjJYT7FiabrsBeCKEKLZRNvFCFIFuVztIAoduA26BBzb4nvggmgnfPIBg6zCDvmHMmv6iLk22sCt+GALd/a+lcXH2QqiVeGJ/YXeu3BShwqIZUlYVZTBZL2sLgU5OXw=",
                    "bWVudSBidXJzdCBnb2RkZXNzIHRoZW1lIGluc2VjdCBjcmFzaCB0aGVuIGNsZXZlciBpbXBvc2UgZXZvbHZlIGx1eHVyeSBodW5ncnmmGULmH42dlsekU1SjRwnWFDKYXHGeFVm0Y7g08KzWxX5dIBrTVUYlpbhyqEVrYoaexeKJgpc2dCq9cVDCWN79atYdvGwyG1sNMLcTltT/QR3ey8JnUV1MxAgq4r6+s3HjLtZ2B6xtsAyBbmUuVA7/7lL09o5QBR8JF/o3iZXfLqQup+uP1nE+zRkMOleNElepaf2/aqcW916Dy2pt5O9n",
                    "c3VyZSBmaXNoIGxpbmsgcGF0aWVudCBzYWlsIGFuYWx5c3QgYmluZCBhcm91bmQgZ2xvcnkgYmVnaW4gdmVoaWNsZSByYWlsPvLHgnSQfaiZFuJW+Wn99atFBRKb2frUpYWr1HKGaAkHr46qrCXRcL6PDYq3ljf7EAX05lHymlraJYiPi8SKoIIdU8J8HFc012qe1GnlF1cmyqltzYrP7DCIdsjZavQGASPEinxJk5ZRISQtT0mCZ2XAOxTXxgGEpBn/qQfALC0lIjhArKSzjSPkoK9ztpjb8rf7L8XilOHZFvdr5gQjtQ==",
                    "ZHV0eSBsZWN0dXJlIGF0dGVuZCBzdGVwIHF1YW50dW0gZW5vdWdoIG9yZGluYXJ5IGtpdGNoZW4gc3Bpcml0IHRvZGRsZXIgd2FyZmFyZSBzdXJwcmlzZYIlfzZOJv3DanfHSbzf3Z+kG2gD2/L1tbUajEWK1VfbFSvCYyE00+lvI57Bl3+KtH6g6La0wcnK+PjAHd3VYHpRoP1rngLoGlB/N0dKRVQqywkxCz1uM1k/fY3vib+e2vqSAuBMZQXgIOO9fvnfJ7LygC4BOb1qbZhzXAzU2c6/ls1OrmhJjwrPS4vKPabXy1o0Gwrgdxa39UMpGM3z0h8=",
                    "Y2hhbmdlIHNocmltcCBsYWR5IGJleW9uZCBzb2NjZXIgdmVoaWNsZSBmaXNoIG5lZ2F0aXZlIGNvbGxlY3Qgc3RhbmQgc2Vuc2UgaHVtYW68kuwurVpbaM17UcVmIQaFlxWSJY+bJuQO98lt/ffSsXO2wosmaB0TGDeikLSLWMU7f3bQQIrC2LduPFLKHyq8cpZ8GIyL+rUB/FJ9BKV6hMVgo6BPkiE892T6UyH33LcgMp1hkUnf92SwdCNu28pL84Rag+PVfnbqBdcgspSH3ql6YrLiKFFi7NQz7kAYEo2NmVKzPwQwDO1VtDdBARpJ",
                    "cmlmbGUgZmxvb3IgbWlzcyBob3N0IGpva2UgdG9uZSBob3VyIHRvcmNoIG9yZGluYXJ5IGFjdHVhbCBnYXJtZW50IGJpbmTrp9exWSHas/8GJf3ihnfk8ZbsKs7MDmuylVQyJYpXLcqOb3gsia3BRKdsXqwm4SeswihUFsJNFkJx0Kmh6LOt30OT1tce7RXn5b3ccm7xVLRNJBm5UPZ/1/iNbV0VO+84XSO/qZmFzSC/A+TTASkWthiVLPNp22PxQvAjftBCxFaKxQuMyUMZMap/xPmCcAIm0MvTkZlI4y05zG3QoJMy",
                    "aGVhcnQgbGF0aW4gcHJpb3JpdHkgY3J1ZWwgcXVhcnRlciBqYXp6IHN1Z2FyIHRhc2sgZmFtZSByZXRyZWF0IHRvb3RoIGVtYm9keWXDY9+Q05lpwqOWDcnCS/QmDq3LrOTUsq3Ndc2eWuEok4692wgIx7DW7Uo1BsNiHrk5Rum2PL9Se5VIPLkqQNEriaGRggC2nrkKESLTPDpDQAXDin+L+PPblbovYFMjP6dq76fLwkZ9X/IAGGJKHxLaPj0j37wmTfh4Cin+MYJCsYuTqZFMoVFaqmc0GrZtbpnEjWvF04jtq+wMajyZoZI=",
                    "anVzdCBsZWlzdXJlIHdpbnRlciByZWdyZXQgd2FpdCBzbGFiIHRyYXZlbCBzY3JlZW4gbWl4ZWQgYWJhbmRvbiBhdWd1c3Qgc2FuZKCxA2HZpvYEr7DGAGUe1HrLAs4R/BYCWIM6fpCHEs7u07MygiTQBY3OC2yJm6ODufdjLKUUVYG+Fhvt8Af6qyTgsrGL9lpUN1jWWYmUEVl7vBdgCDQnyC7fqM6mEuQVOaMC4Ebl11+lDfo5tUmnRQaZ95BeA69jRRDHxOz8EWHiZT2NrsHJP5tODsqFydTjTmdXIO3pWBq7SwAfMNNdevo=",
                    "dG93ZXIgbnVyc2Ugc29vbiBjb21mb3J0IHBsYXN0aWMgY2xvc2UgcmVtZW1iZXIgbWltaWMgc2FsdCB0YWcgbWl4IG92ZXLFSUfI189Cc2hcwytQjsm94NXG8PpYrJlScWSS5DUDBPmbawr5rUdk7c+CrzXcbmN14qQtTFnhKfJs/3qwY/qvJbErDU0PzRaCwDG5qGUx/FmGlNNYMivY94SQefeoaGL4ESvP1eCbEPl1IcYobagj8pkHu+2ZD2c6ErA7O6TSCps+VHrAYWOy8aICz4ga8YY0R4t9img9VltKDiZ4x3/v",
                    "YmFtYm9vIGdvc3BlbCBwZW5hbHR5IHdhcnJpb3IgY2VyZWFsIGZlZWQgbXVzZXVtIHdyb25nIGlnbm9yZSBmb2N1cyB2aWRlbyBob25leSLQUnslC3WjVHjEzG0RudPczmDPhoYFFSXy453LHt5rrMHaE7DuKwA0DXBUmvRaeTJUZJbYOADpCAtBCMgHRchkswf7qvo4xr/tMalvV+ymkZ4PYVoVWg210lYshBzzRaevgEhoSPLiJASk1AtYumMLc4o1fr4048+e8EnkcO3Cy35Xo3PqvucW1TIZO7L+DjRhBDguQlZW2gGdyIznA9s=",
                    "YmxlYWsgYXJ0d29yayBob3Jyb3IgYXVkaXQgZmFzaGlvbiBkZWFsIGxpY2Vuc2UgaW1wYWN0IGluZm9ybSBwb3dlciB0b3dlciBnb3JpbGxhQdqLdCYAMrNxCIrGv/MoL5hGE92xABSPj6MfgOMRc++0mpO/iMNAFzM2ZJBhKLM6C47wgbU+r7oU4u2C6zW0mu5iBDQh8XcalSMAdNi2xoATWWbEs26wcjJ9TB5g4tC2yjDTACePerqI0GGsm/2ii4tml8N/DW4hlns5go43k2IqlFVTNVZoXWvJYrVz5vv3WoYBONpz7OhZntnHWSFrrg==",
                    "bWFpbCBtaW5kIHRlbm5pcyBjdXJyZW50IGhlYWx0aCBtb3JlIGtuaWZlIHN5bXB0b20gdmFjdXVtIHRveSBpbnNlY3Qgc2NhbGVuFWRpFUsaxG5EXuM75WQ5bTgLBPVcaLN0kT80Q4NpxApLmD9AejE1/5kZ13Eyft2jCVT1uBaNyVw8kMxxb58F+CthiAvFoXZR6od0Q1oDrvhHDzJZwDJ8MrP49tJSyldepsUPmmVM00pKG4F3CzwdppDYCFPxrxSKFskZaGDM1LYLzlGG96JufRUlr9gGu1/wPUeWMzzDivX237HuNgSt",
                    "Y2xldmVyIHJhaXNlIGlubmVyIHF1ZXN0aW9uIGNvc3QgZmx1c2ggb2NlYW4gYnJhY2tldCBhc3BlY3QgYW5udWFsIHN1cGVyIHNlcnZpY2U6EAutTbVTdqGv8p1ucE/34D/9tH2cTs64k1RA8Otu6XCIRZpJDzvUyzBp26cmagaUR8q8Un6SXXUHHCBnQUFkA9djJKkqp72N2aeRMC/zdiN3Cz6lPzjDqb5ywtcanQ2W/6DlQl3QOHnKqwkcaNVBGbRY7QhOcEvD0pRkfKlMqE7XKIoDEDYhRHPKtcc+ovip5pf8yZl7/fi18DgIjwsj",
                ];

                for (ind, item) in items.iter().enumerate() {
                    println!("{:02} - {}", ind, decrypt_s(item, &key_e64));
                }

                return true;
            }
        }
    }

    return false;
}
