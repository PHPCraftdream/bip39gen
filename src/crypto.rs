#![allow(dead_code)]

use std::collections::HashMap;
use sha2::{Digest, Sha256, Sha512};
use sha2::digest::DynDigest;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine};

pub fn generate_entropy(pass: &str, size512: bool, rounds: u32, log_each: Option<u32>) -> Vec<u8> {
    let base_s = "SHALOM-WORLD";
    let base_str = "".to_string() + &base_s + pass + &base_s;
    let base_b = base_str.as_bytes();
    let mut entropy = base_b.to_vec();

    let mut hash: Box<dyn DynDigest> = if size512 {
        Box::new(Sha512::new())
    } else {
        Box::new(Sha256::new())
    };

    hash.update(&entropy);
    entropy = hash.finalize_reset().to_vec();

    let add_itr: u32 = entropy.iter().map(|&x| x as u32).sum();
    let itr: u32 = rounds + add_itr;
    let mut last_progress: f64 = -1.0;
    let show_debug = log_each.is_some();
    let log_each_v = log_each.unwrap_or(0);

    if show_debug {
        println!("total: {}", itr);
    }

    for i in 0..itr {
        hash.update(&entropy);
        hash.update(&base_b);
        hash.update(&(itr + i).to_be_bytes());
        hash.update(&entropy);
        hash.update(&base_b);
        hash.update(&entropy);

        entropy = hash.finalize_reset().to_vec();

        if show_debug && i % log_each_v == 0 {
            let current_progress: f64 = (100_f64 * i as f64 / itr as f64).round();

            if current_progress != last_progress {
                last_progress = current_progress;

                println!("progress: {}%", 100 * i / itr);
            }
        }
    }

    if show_debug {
        println!();
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

fn encrypt_n(plaintext: &str, key: &[u8], iv: &[u8], rounds: u32) -> Vec<u8> {
    let mut data = plaintext.as_bytes().to_vec();
    for _ in 0..rounds {
        data = encrypt_once(&data, key, iv);
    }
    data
}

fn decrypt_n(ciphertext: &[u8], key: &[u8], iv: &[u8], rounds: u32) -> String {
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

pub enum ECryptoParam<'a> {
    Password(&'a str, u32),
    Keys(&'a Vec<u8>, &'a Vec<u8>),
    KeysLink(&'a (Vec<u8>, Vec<u8>))
}

pub fn make_crypto_params(params: ECryptoParam) -> (Vec<u8>, Vec<u8>) {
    match params {
        ECryptoParam::Password(password, rounds) => {
            let key: Vec<u8> = generate_entropy(password, true, 100 + rounds, None)[0..32].to_vec();
            let iv: Vec<u8> = generate_entropy(password, true, 111 + rounds, None)[0..12].to_vec();

            (key, iv)
        }
        ECryptoParam::Keys(key, iv) => {
            (key.to_vec(), iv.to_vec())
        }
        ECryptoParam::KeysLink((key, iv)) => {
            (key.to_vec(), iv.to_vec())
        }
    }
}

pub fn encrypt_s(plaintext: &str, params: ECryptoParam, rounds: u32) -> String {
    let (key, iv) = make_crypto_params(params);
    let encrypted = encrypt_n(plaintext, &key, &iv, rounds);

    vec_to_base64(&encrypted)
}

pub fn decrypt_s(plaintext: &str, params: ECryptoParam, rounds: u32) -> String {
    let bytes: Vec<u8> = base64_to_vec(plaintext);
    let (key, iv) = make_crypto_params(params);
    let decrypted = decrypt_n(&bytes, &key, &iv, rounds);

    decrypted
}

pub fn check_first_arg(args: &Vec<String>) -> bool {
    if let Some(arg) = args.get(1) {
        if arg.starts_with("***") || arg.starts_with("---") {
            let arg_name: String = arg.chars().skip(3).collect();
            let arg_hash = generate_entropy(&arg_name, true, 1_000_000, Some(200_000));
            let arg_b64 = vec_to_base64(&arg_hash);

            // println!("arg_b64 - {}", arg_b64);

            if arg_b64 == "CYtkPXk+QhU6LIO2M/AeK+AB0eTAd8Ss6Sx3QAypSElu2H9jPqTyynwuy3+a8QlsGUNKZmfZ7bv0jRKUopuJsg==" {
                let items = vec![
                    "ZGFyaW5nIHJhY2Ugc3VyZmFjZSBzY3J1YiBoYXBweSBzcHJheSBmaXggc2VsbCBmYW1vdXMgZGVtaXNlIGJsYWNrIG11c2ljV6ypEycjutweG7UcKlTA5O3cSwItzh0yWu93kRR+cT0XPELkSWvjGtTkgJs9sya6n4UFy+sfLNXoqvpg+KAfr7pL0QZ8UrNJrsARje59VDEW5bmUjkuVlegsnf4176kq2dGZWfabdW1TqvMDzaqVNlBJill6sWKUIyGlQaNyxuk3dXZmF9d4t/sTK5BEIPwurUR5jrJT7uPxD8Pt9NSYMxReBNy5J2imc8syMyY6bDGFSdCT38Eztpl92bK1xinJ2WetXsfOSiuMBQHIyDNmSuLR0IHzjkTQex1VTxu3PwFpev/Dq/SzdVL84nDd5FpMSwmXt16OzTMzjGQCD1pS95yuWpKAVx+Th6Ik/ZT4gVCGtfntXcB0ehojjKJp7ziWOa3rRkUm3TCcKt0x6HsLc+H4aAclLErIJSb/6BTkFK4=",
                    "YnJhdmUgcmVjaXBlIHNjb3JwaW9uIGVycm9yIHRocm93IHdyZXN0bGUgZ2VuaXVzIG9mdGVuIGhhemFyZCBvYmxpZ2UgYW5ncnkgdmludGFnZUyp70EdF0K6BC9YhGctNGOLFm/UidqEPS5ir4//KdVf+4pxi+JJvOEucRLw1HaqGjMf1P1Zd82VIcaCRO/aBpFPbSyi8mXQW+bkmjJ3oxxn8R9KEcvRgk6leo9ucjJYDtC0hwfvG1jEt3KZ5JRHiEtAPhx/apR8t4uzPFRNORhMDug0iGwh8i/kz+7csVd1ve1tqGT/PlbpLYCIuGiQ89BCsgwtXdeROxxPHk5NgQNP94HFUq7gcVjKAfBzcdRJQ4fuaDJXIAkiLIXFDPt0nK0QMGDMooydAtjR3ZxNyjWBHrCdKp066ugdetxPOZIbVMo5LLgP8WVrn92cvwJO1kwJEID76IvUb8TmqOyzEWA7gCIMMzKv6NtaPXA2n9ZENMKBmXCPpB3sRNiLRITyMDpknNXotn1jf8UMXPSky/JT",
                    "bXVzdCBhbWF0ZXVyIHVzZWxlc3MgbWlycm9yIGFjb3VzdGljIGFlcm9iaWMgc291bCBvY2N1ciBzdHVkZW50IGV4ZWN1dGUgcmFuZ2UgbGlmdIMjfXxnecSo9+VfyKFXRevhU7ddd146PhCq/eZ7yIdUvB1d27eyTv2I78dncvTmUqqlW6aV8qJ37aFJDzCzDcxAw/2d9ma1EMe3KgjJj872d5OH2uGyA5XgZfj3qqlmhMieXwjgaXHhpIkaqCX6RDXT27SDkl99/RhalBDK6h7aDWo9Lf6KeG6C3ZAsIjrpHPjPHWP7/N/VOI/3taZef8Er7ibYVLZKSpoQfY7xYJlUaU22TzBdnsHN5mgOGm72QiNRtKuGhjc9kTVBXvCefJqFxlRwCg0ip9C/6E5ZCc1XYU7p6NAQ26yPQ7vQUcZZFxiLzsZsGHXhtc6nTrmq0DKH9005/6ygxUOG8m6YONtfcmfEuuqlXUZxHDB+JemA0EQ22kogV+o76gxQ41vAski+jcgLhtB2XW59N88DPdiL",
                    "bWVudSBidXJzdCBnb2RkZXNzIHRoZW1lIGluc2VjdCBjcmFzaCB0aGVuIGNsZXZlciBpbXBvc2UgZXZvbHZlIGx1eHVyeSBodW5ncnl4gK6LsrZPgBkZBtfhbE6/YPCxox4jxLJu31Hn5oMK6f578q3qGi6oP5sfnA+/hXlX01jqNSYpw6EI/2ayAjMg8OyDJDtu8/QudBpWG7gZczwfXaFkZH53k9UKLvaV4TlsX9JuoYtgdw5zan5WBMFEUGhPGthiCQl2x3qY0Nb7PEWTqBGG3Cw+DX7/7+LQ+Uuh+TWUWgJ3JwfW38sTbzSIbqZ6PT/oy2K58MWRMaY3q7u86ppRVGrXKaIqKX3eIA/zq2A5nd1fiAJVam8PTeICNbJIooDR57kEx/FgOkhsWmt5cBqAfz1yT8tUFl6putBSCGdNAGN3r4d0N4P2etaiQ1sYO3uBORGaxudrq9Awf6tl0drB/OiPebJireC1sr8Zim0xBS1c23wckhgL3SqaeUAcLh6fTUhSb5GICdofDg==",
                    "c3VyZSBmaXNoIGxpbmsgcGF0aWVudCBzYWlsIGFuYWx5c3QgYmluZCBhcm91bmQgZ2xvcnkgYmVnaW4gdmVoaWNsZSByYWlsv2oKL+U+WXLd2TH6OXyRR5B3DJUqYnFuGwCd9C+3yGcJzhsV+AtkDm8ayAiT+gx9a6S2KXgHuhmu6Ugl6bDKqyzS9lUvnb6mPj6EbuC8XAyhT1Fqs6V6Ae+CctVjT1pwfEtP/SfrpSZtiCcWsVlU00hv1Ul+MMgPSx5+P9g5RNN4d5l2vzZaTAxlEOMrCChDwun8o5KffRF3JCrTTPBlHoJmvM+tSoXjkSfQuWlj+bRxOTYb/FzY6tnd8QpYO3KSYOuKo5gUVYFAK8HYnKXiDx55NH0r0wzKLzdaSE1yDw+GMrSvcjvnlG+qf+AWrMiE9GWB37ZfQFGORgkidL8bY5/SdrGorCGB0MhzZ+VIq3NNS6MAxLhPQWwLv53G22k4uSd5KV/4eAOOxnYHKCHxLv+RtuT1OzVxkLZBdHgjy5U=",
                    "ZHV0eSBsZWN0dXJlIGF0dGVuZCBzdGVwIHF1YW50dW0gZW5vdWdoIG9yZGluYXJ5IGtpdGNoZW4gc3Bpcml0IHRvZGRsZXIgd2FyZmFyZSBzdXJwcmlzZfnQU8gDnS/dCf6d/qRlFjAO1zsYIUnt0B8zOpVC84xlbWWYjO50bUoVTOgJdGFWaD3UxQDdKr8famu+aGpS0r358o4O3z9AgazvD2wHPykaULreElefNGsVwUSlVJNgE90WkGVve7ti+PuIjrhgTYwPKfBQmnJZqFtFpv+o+4f3mZc/Yz5pW/TX1i5QoNPoSLvz3hPpP6x8UDFQ4qTLrTJS4L/yaE9M+T6O98misnBWghoSc6e/FPLN1nHKSQtS+Z2vXqcKIvFt8OeHWQ+gs13IV1uLOHV+ImCizoLarelgYtCysE3DM/R2LxG73gVbh2nO67RyVQTeJ9vfn5e74L+ngQMhcsxYrNTBnpSrMf0zjr1QeACCOaMhV+leN+hq8dRpBsPj50sdqVxK53YjwYlqpCBjQ/f9J5N7GAhYaqlA",
                    "Y2hhbmdlIHNocmltcCBsYWR5IGJleW9uZCBzb2NjZXIgdmVoaWNsZSBmaXNoIG5lZ2F0aXZlIGNvbGxlY3Qgc3RhbmQgc2Vuc2UgaHVtYW4UAv4Lqa7XRtVqxY7gcZQESzACj73Hnd4I71lb348I52XGjdmy4mWrvpKnW/UC4zlnOBLhMb7TbZa/R9NCWYkn+qHI1JotozBGEL/iC9ovJ+cigyzthyXJ+So/TmJOeUosVLNhn+jsx0I+e+nnFhuVJrTQ5byGsn41jAh1JnTZR9A9Sflv5iibCUYRAhUjqT5n21xyxBqLDeCrsA2H1x+k033fKlSqZjS7heK+nVhKPkBLUyD6D2FsxxgQ6UpRrltmXR/GEoKDWV2s7w4xNKoE/vQrwlFcHU8gUrZXqf8dkvY1ACTBe1JY3kVPrlW4rlXKXjGeKzy7s58QJfd7H4CPAK+eOhkBhdHCqTKLn0H8ITGAk7y+m8ro5/nj8EcQWR+7gtEVbjRqprpeor8TcYWcHXk8UgwxTkbpspU84dgshw==",
                    "cmlmbGUgZmxvb3IgbWlzcyBob3N0IGpva2UgdG9uZSBob3VyIHRvcmNoIG9yZGluYXJ5IGFjdHVhbCBnYXJtZW50IGJpbmRWpQivtyN7XC+XGjtKlk+ROZy0QUF+b2M5zvSRL6V19yY2J14frFWT25yiI6YmTzFAsaY+7CdSDKj9UFX0zNMVt/LpgtRW8EWD8bfKn/Y1GM2PDxUx1wE2i3tsf0O+A9M3aivX9bQjc+YqkE2R1ZPPJWCIeNjk1WADRjuEj86RwsJL1SBhJoAetvjfYqqtT7MSKvQTdQt0kRfgrfDSg/eUxTFm4Msto2gG0I6D74pWRCsEt7jx8L32zNtwwS+45IYmdu7/icyucuRz9tmNlpW8aPH3/kT+GoyCpCwPMGzevot5zz01b/Ri9DMVPBU+YRVtBgB3O5/kv7o00xn7t/KR33g33ONyy3o1jDHuyv9UaT9vIGSzIXhTgyYyCyR9pnZ3PX9iHTThqHH0W197mTIUN5cUdZleO2N8i9ZwOWosUw==",
                    "aGVhcnQgbGF0aW4gcHJpb3JpdHkgY3J1ZWwgcXVhcnRlciBqYXp6IHN1Z2FyIHRhc2sgZmFtZSByZXRyZWF0IHRvb3RoIGVtYm9keUdqbyidgPjrZzXlSd4O+OMLm+mFq7NL3p3Uct0HiOKOaqGZFRITriJx0JzwJWRwr6SxCScW/NjIfjbRLxmM9OdE6hT+0PZYM7QbFrbg/EdeuzQCZAqCRQjPcP22RGmdNukiDK5X2n9tEFWw8VWoboCWQNlu5WX2anZqvSgcXoAKga+83Gjl4YzXOU+9TKut69PiICECGVwMrNhGv2zy7i4nG9PhtP3cbp84FXshPQOd8CSu2KwdQ+q5RnYmQOJkpS9VYjNxYVTIQNnbn817xBbgiLK+5Ob3aljkC4F64ewHm3R3hXS4c+nkoGyjlAOnlZDk5n2oHFq7/YENUMOPR+1Oa9utoAlwPDUVaWxqo/EYZ/s1FL3DEcuwB6JLCJS4SynJPbXp00nBJckOH4TIYMznQQcEwNu8/L05GkAm15Ri",
                    "anVzdCBsZWlzdXJlIHdpbnRlciByZWdyZXQgd2FpdCBzbGFiIHRyYXZlbCBzY3JlZW4gbWl4ZWQgYWJhbmRvbiBhdWd1c3Qgc2FuZLOAuZIeDm5v/6WdGyY66rrNE/Q/Mpj8ROJQCs3PXUnZTvAwTdWmS3ovNwmGFHbz+ETB2IPVZE5T5qg6KeEPRVOLp4o3M85cINPIYz9Lbilio2sPWMbtcFcwuqWsSY2kjqeWHkyB4bQyAuYpKWM2+eHANApOGwL9vTFn2JlYprAt3P4rw/6JOg+EuSfXFyRwdBXEMcRgdnyaZPMz1bQahIIqLYrOXlA5sKNm/Dv6NB0dOlIITy7il/dz8Hafz4j0SRaL5Q/jcmY10RV0N0dE3NKXHNd6aovdU1rYayANpw4o+Y9Qk+oNyqlxlDQ6yP79JmhznUL3ev9mkDaeGxl2fboM5IxZ5Hn7zMe7oBdUlP2S6fj/qQvgIHjoVENWcjdMK9WvEqyNEBgc6H1gtXTZBk5xZcDQEbz1R9bgzhoY1rOm",
                    "dG93ZXIgbnVyc2Ugc29vbiBjb21mb3J0IHBsYXN0aWMgY2xvc2UgcmVtZW1iZXIgbWltaWMgc2FsdCB0YWcgbWl4IG92ZXIqntCWRFs+wPCdSh1Y979TenRd3Tx5/jBFBujkfCyRSHixse6Fm8oCpKiEN39JvJtarldiFWfTiBDVme9X2KGl54LgziUIzWrSqEK34S6MTX+BzyT8JS54DWmY5jKqmZPcVl+GP8/L81mx5L1x6jj6YcnZlAJf0HsDA5IOYakNtbXOIdfZ1e+pc6V7ak5B1RcjPDgev644kTjbUtsTRKEtN1PHmqonLs5uZRLPmOFK570IHCDttwYds6oe3poYPEmBw3BxNAlTZjjAAIdZZyOIRugk+OURMZbCd1mtomy2TqxzB2joDfY979xQ0mcklUSh6X/SPAN6+eOfye7a8fVf5BaONmtmHr29sLGS4xyYCVnTAaOQJ6i4dj+Uh4fOtZbr1sGVVseYZELVCcSZCFGIM5BTZTekpCa5A4a0fB3Fsw==",
                    "YmFtYm9vIGdvc3BlbCBwZW5hbHR5IHdhcnJpb3IgY2VyZWFsIGZlZWQgbXVzZXVtIHdyb25nIGlnbm9yZSBmb2N1cyB2aWRlbyBob25leRNjXZfgi5TFgm6TehNRBlMLNoB17yGoSSyxDOXK+56lPG6EM6KUCXa3Xp40r0deD0nXkl3Ic0l7/qP1F1XJt1qFuUbo7LjTOIPQn3c84Aeqojrc0TDP89LR5g5myioYNkt175oH/eLJJEIUbsMHuK5JgRDeiJx6fIdcp5KBIMOONUyJrD0T8JPS1RgAv5YUEBYIiXJrglta6MesdcxDcbcF4VwR3oBIcPXnr5zvg8zq4QF0ywob8FFtgletM2iE80oxTTfpHNYDsdHUm6i73wasBUDtZ1OOMdBCYsDKsxzDNYy5gJzzFkzj6j0GhfpSH6sN9edZBM9SuxmCw+/MiO5Gf2OHuu43L00KOEVrSo0pVHwaKZiWfFnmClFflH39IWR1A0sCVD54kCYIWm6WXHzSez7i0ySZs/m4MWFDLx8S",
                    "YmxlYWsgYXJ0d29yayBob3Jyb3IgYXVkaXQgZmFzaGlvbiBkZWFsIGxpY2Vuc2UgaW1wYWN0IGluZm9ybSBwb3dlciB0b3dlciBnb3JpbGxhyKiWN5ScZKJnb6e4SerfJiNwCNoPh6ZsyfWr9V+SqPJz7PH0tN97R/ztX/kkgodIzIDFK/B5WxzCTpTNyNos3clMpdWc5NFr13eZS2YBwqg4aTul6NCt4H0r22AgPA7mbnOHktoSfvx9meK/6ofrvVPsbg3HAYmQISNMhCsd5TmJHhUQy59rrrp7z4zK6bC7lPFZebTVH+mu4r642u6O5Wh4Ah7sbKYS7smom+9vQ/y7kEEED7KNtXvwVimV5nAP0bqXhXIpGYwiPaLXoLuTGjfiPmUHP6gqKqvAo8Ac0OlIqadMpFVastFTCW0iyN87wBCvC9uIp0YM09VMcXjSqRw0rNz+MFSW2HLg4CWF4nYoxY47LHw8cErQymh7K9lztp4ky194D9DBJsvvwY7DniWZIlfyIWqpFrpdb+CGPPQ=",
                    "bWFpbCBtaW5kIHRlbm5pcyBjdXJyZW50IGhlYWx0aCBtb3JlIGtuaWZlIHN5bXB0b20gdmFjdXVtIHRveSBpbnNlY3Qgc2NhbGUGvFjV/i3SDUqUeoUVeTvjkYsD03le+cHB3FDoWq0IcRPhEx7Isw1UJVnkU1dn4Q5rV371tcRAPjiIZev4BXvMbxGq4wF8xs9VEMYQJzKfL4WZ5F8IvUgyOqevmBMEjFIb0F+VRc1Iu6e06i6mH9cSnQ2su5QK6tUn7o+YqifLHNWCgwQrbTAqtu6OfpeMtbL+kyNPZPgsSvEpCLPBLNR1QFIwcg5R8InEFkxKniN0QJhDZlxb3LBGc87A9j0m4F3ltfWV1r96WLI1wcf2TOGhozsKVAB4PuuBI2kaz/1FiAjaRQJIDVIK5yjHXuKynsY8zHdb7ILS1aJJz2YXwAECTN2OlZJJcpyTibrOivRCKluItF05rAMStBN2FZDwjAsbcSxq4Yvq2QPScpmip0NFXjyHgODzps2aOwb9Zh0lsg==",
                    "Y2xldmVyIHJhaXNlIGlubmVyIHF1ZXN0aW9uIGNvc3QgZmx1c2ggb2NlYW4gYnJhY2tldCBhc3BlY3QgYW5udWFsIHN1cGVyIHNlcnZpY2U/ZEhxBciwMN2jK0oUT8tv3ba9ANFiTYaZZBI3JXHRRRZmdzNho28MFT/YSk0imUogOBg9cZYSApSnrYEp28uGMIICR9ok3yUDewyOohTP1O9UZdSXjTm/YGI7mf0jydLSCV2yG+b9hXjdQsB+OgC1yg207xwNMsifSTg0bu6V07dmXIjMmUy6jW1YE2fInr55l6FfHGvqeEtwyn0mOwTxpyy1kF24CX/yvxZ6AFBWL3imhyMZBsptctlkhYalqffXjKQCmvTbWwAO2ePss4R40s/9DJizN5ztyTErgwm/zJdyDHP10wlkNipKgEdgAqTFiYUywai9VJX2H3k6hjqhC0aTTs54I3Ev5QiZ40ylJt+hoJ9QcTF5NYuRBW2nPmaKCTYkgB9WUXKnVFZYU+rKo3BJfzNeg9Npygy/vU84Gw==",
                ];

                let pass1 = vec_to_base64(&generate_entropy(&arg_name, true, 1000, None));
                let pass2 = vec_to_base64(&generate_entropy(&pass1, true, 1000, None));

                let key = generate_entropy(&pass1, true, 1_000_000, Some(200_000))[0..32].to_vec();
                let iv = generate_entropy(&pass2, true, 1_000_000, Some(200_000))[0..12].to_vec();

                for (ind, item) in items.iter().enumerate() {
                    println!("{:02} - {}", ind, decrypt_s(item, ECryptoParam::Keys(&key, &iv), 20));
                }

                return true;
            }

            if arg_b64 == "5zkJhvFS8anFTJEbtH2syyOusU13ZMaocTfycT9A79ZdAWjrBcoBHL/QuKi1hqdwfAbSOXGeH82DWUBYxjw4mQ==" {
                let items = vec![
                    "RWxlY3RydW06OjA6Omh1bWJsZTo6YmMxcWhobnB0a3ZyaDRkMzRhczhtandwNzR3NnZucXQ1NHE3ZGx3Z3l2s3N+crZZ7tiiRukX5Px2JwYGhFdOZZziI28XX9fMitGUBJPW9V6+7mkEsiDWgZ6ypHRpyqY8bmkkZUu6SfoXYN3CWP1E4UbREq6y/LCVOmK6oDIRsW+RmbgRIQWPPJCMnRhUtMmh/gBRQTHBy9CgSFDtkQKUxZgXejr8K5pIhzikrNx+ugsKaPjODNTo/OeDIwZuBz0+FsMfvxKjwj0HBsHYrg7njr3kRxZEwBt89DpoZx1H401oORB4c26jA93umMhWEE6ghXd5bD9ZkE1XcwFJ9VBQZV7jlD1+ygQ7YuLVpq5TiFB9cAQ38lyx9N0g2EVXZK7+YiOkzWozZYvifDYbDc4f1rHUH7fUJugFzdNuG0TNzM+vAWJ5oklBzfsDPI2A6dCt5UR/qDEY26qJI7pNgzGLmjjVUHRkQPoJp0g=",
                    "RWxlY3RydW06OjE6OmJsaW5kOjpiYzFxNG5zN3c3OHVqdndncnkzeXI2d3RhYTZoODg2NHJramxuZGRhZnmsc8IAm+ZhzGYFPgjmiIZiwlrsLh6Psjj50/ntRg7iotlXTlgKaiG8T0221O2TE2QSriWw9SDHj1WK9S4XbEe410NYbB57W9F1OR+aLjwNrqsAWZgjl1WndFWEhOajbezaYySfuuFMGOBDRzH5MwpiLEtfAcb0eKf1ZEgD2/XMtd12OAXKeu4CBdOKwvq4YEFkqZ82ARlZuanpDHongIykxtbKypgTxSPkZe5Fgo+OK7EQMy9BCNvbX99G6Ib05kHrdhAM4SNrMLiudN8q1OCtWgQJ4S/ORKJePSla6p39cg8WSY9/NxNVEBtXfeoW2L1A09S2qf/tGV4svbmOlJyGNq2CQNkG73poDa5ERIRbtfLa8C/vwCeUWlyeKib6+FmkVgrFE2a28jwYUYmLM3HFRsIDH4TURhOc1QZucjxbZw==",
                    "RWxlY3RydW06OjI6OmZvZzo6YmMxcTR0cGwyOG55MjdmN3VxN2UyamtnN2Q3aHVzY2tyc3Vqc2t2M2tmDxVXUMDWGp2HZJhsjQfylX0zSoPxgJ3RkhAj+86VqPJFdxrV1IFHNqQ7ZHjjcKM56MK76lSUnOj9sGX9O1tU1seKEMjnAgL8UXPfjh3RGz+3izQTEFT/CurNE3kzVNzfB+y3KdXnwPdqMi3ACCRY3i22k2FN6O4WWSP7A81DCW1ZNPWxomRSAk7pXR1K4hWLsh/9PgpjyNhM0w9vfGadiApG98zGHEF5xGcUsv6D3KLpDXJYOo9A7CvYJu7a4F2TTplZ5cu34MnRsBJQYyYrkUpSxw4AVMZt3i03CrQpervPT+fP9O3SNSo8IG5hipU/XSzryrKMEg4osZNr/iOQnAILGXD4+crFWb3FWv2fqjlGqYHkxS+ppfxKML4ZUuoQP3smSzMWIx7DdgwP6I7fVf1Uq7L+ro03hnDV+AyzVMg=",
                    "RWxlY3RydW06OjM6OnVtYnJlbGxhOjpiYzFxbmc0eXloanB3azQ3NzU3MG5nY25wbnhuNDB6ZzNwZTU4c3ByNniyjIch25PyNJxXCt/Opsf7z83+2mzTG0tZ2n+H14NX3RDBFKkp9AmBR+VWsBwyB4a0hsJ+ohIfBp/hzYtD7oEEcYdxIyYPobkX3YTiPGtiEiA6UmTUKbff43ll2QqPRimvbmI8EnAAsg5IKjKfs/L8i0RFTy/FkXEWCzwF/zFY0vimWGnL30T3y/vU8q45Vd50eU5SqDVAU/Bz1tnEbhYM77lSZxd4NT8zjUGuFFbxPlW7CLqJTnYTNt8TtaD25A2AKLbveq+W/D/Y1/vs6fNQA9Hnc+tyRYBlZf5yGIoHuNZW71NnqeNQfFidhks0t16NR2u+kLhRRjPcXnuL30BeDTGotCqZqI6giWQyx4T4DcrjZUGqx9augspDofhaTUk/6tZHnTI1aDsYXmrY7XipUwxzEr1u7e9kq1D914CJmg==",
                    "RWxlY3RydW06OjQ6OmNoaWNrZW46OmJjMXFycnFqM2tjd2dwdmpsazh2cHV0d3dqdDdwNzlndHU4Zzd0Z3Q4d35K7+Rw7BMUek2e6FGQaiGnNh6TY9VIK+l/ea0iuSqblgo2fAjOHlYLFjHbTsIXbrU0UVazNWM4fBIi6my9p1oB9Z3BK9YGE0qj0FD3jv4M2dQ09dRsTwt1rRtVKupC03YVRb3U3yqPs2TmiSvyzXg5dAgDdQF2F6MLWkII9BkvuwaiPJ1/kPQLQsK/gYvJnxnZY/KtgA8BZWEXmuZ/naRrL92k68ZRZjWcuWygOFJjJ9SsK8Zlhesn9onuM6osAFvPMaNGZy4QENik+yrJIwrY2pnbzmVPICuOWSOCtCPQ5T4MnVX0ac4uB4wDOG8xmj53IWKyKHhiSS49UcNVxtqGqor1G6kA0TuKvKpNYVtxkqw3QxJ/JNvcHMfkUFHk1JQSx/QNJJiK87V2T+s6AihN9nYO8XoULuIIeM80s+4+",
                    "RWxlY3RydW06OjU6OmJhbGNvbnk6OmJjMXE0cHNwY2UwNHQ4emMzdGFkNzh2dWRtNnpqY2RqdGoybjd1em15ZevUxDINxsUzAE9MclwDeXGxOpliY2dJHc3ehoofv0jNBuFqyj2t0OW7GHmxL81YxMqWGFZLAvcBfY0aGHmeJkCilfRy/s6n48N126LJ4Hr7YyDfQh+FyV7zdqRHrmJzF1G5Q/gc11X2xbSfAlZ23nqQPnm/k/aO7SwJZlnE4NfKvCZXuWw9xypjJy/tbICm0K49IQn/qfwBc5+xq5YOSvqdrpXoZqWlwEo0hDrD1TlOwxRuzZjpza2KPPX3W7on1vuSdr4x+bQHw2m28p7vDsPCXZKD6Kj7ObARwY+sZg/jg78vBufRXoftzU/ddtK7OhlhWT+H45C9QTNVyOLxJy6thxenEw+8QxlY6eBW4Q67UB+vlWhHeLO9O/k+1rf6IiKgeXWH2EN/it8b0RKQZ8i99HnZyZWENq95TPfM1Uw9",
                    "RWxlY3RydW06OjY6OnJpdHVhbDo6YmMxcXZhczY0ajVzMzI1eGpwNHVnNjRubWU2Zmd0cmc3amRkcWdqMmFnHZVbhsNmpZEaV7U1z07j5nlN0mLkq0/wwEC2TiP0OTk8CnxquWwLTGa0Pc/OZJ50r3JEzdvt7Y/v9s/vcGtavdlmXVE4CLWekV1qQ+5uYJxs/zvT9mR1trcmYNhjghmIXaPEf41ZZtNS1ODbxwcT1nndXS3P7I03rW20g9lnjBFjYkTa6A97+Cteg/dgKaaPZv+qzplsiqz/JGXpO6Piev1yseWfe1lgKtNprnkaOUfDA4LM8BhZNfycpZrCgsPdQf5QFjPIliUypaxnDaKRdRQbmbPnwVHmgQvkitOr+JTd8Fj1dsAqNZKhAJZL7ktnAThbF49+I8FIPH/99F5TX1g5OJ4cPC/L8z1dWXmyMS+MmcbPbCqUX9mKZlpVgCvgHDV76GsOqGWiPJ5cD6dP9W0O2p4PJVm1Mj4A5wdk7OM=",
                    "RWxlY3RydW06Ojc6OnByYWlzZTo6YmMxcW1oZGE2ZG1ydmxoNmV4NjVnZm40bWRoZ3pyNzY4YXc3cjM4NGhuXZOQyq2t6mnAjT4REmU9jXK+6lEaKrMUJijHmoAAzR29kLCu6x78bcM36eu11QyYGFWKiv4LMMgrv3TnWEeIR6jHLFiG4feLgMzCZq2Vzw5LwXlFeBJYinlWG/PbBs0tutqu4HEdWW1Gu5MXvwW7uK7H5TZU8bZGZlQZ263EkCRtvchoAlFozyeIYzFyrXF+Gd8br/FS6iOIEJLWmbF5ffmpFBv+ZgjpCE5CwDbvWOsA4YUKR+AwFlEahSt0v7spVFGI+5HWHtywoFo1HpX29sW+OmsPvODc7OkvwsUtcGeyfIIGc+pXhpqm78fsRsr+1UBlzosEJI0r158ZBtPpSOfmRAxEB3yIkQa/E0BbQOLjbngs653qXJCy+dCFrj0Fqw8K2ipZc6ph32WjjuFg/HxJcgpJErOs34Vsfy0K8lA=",
                    "RWxlY3RydW06Ojg6OndpbGQ6OmJjMXEycWdwZnMzNjBnMmhrNnl6bWZyZW5xN21lM2N5dnFlOGdqc3VtOfGxB04QwXHRLoafe9ujgtwAnuUG+Wc+rUfnCTKXotJgvQ2a/tbI3u5UVwMeC0juj7k+sNqKyttsdJ30uQYLaWcP+QUe2J0OKQk1Ab7N5/5GN7JCMqD3MgrWkdOdMtFVYfe+BtES43dZ9nWqUqm0szZLtmqJN0aGl7K1/QJ89d0wU9iLJpT73XoZFp0ZltFVuyOT4Os35p9UCbLiK13hnE5s8CNRs4AKiJA7ARwrhZCNOYcXCH91O4XsFv3W32+HKx06dUpjK0mvzI/PAXygE/25odF8iNxmHwDSFRy0cefGRGYOF5q15YofzJUV0vzoqXMzUEjxrhylsQtaktgwlS/4wDkqwEBG29AyaP2yzOlzYOTmpNKYvl8qcOZ3AiJa8EjnkpHh7h1Po3+47IohfjDTSbQa6IvZFNqlEJuzU30a",
                    "RWxlY3RydW06Ojk6OmJldHdlZW46OmJjMXF2czR1NTd2enlqbXhucXd5bXd3ZXR5ZGFjcWxlNXVmdWdlMzB0OBOgmS7LtfjehztFFYi/EB1eF996EG1uFtUw3b5qP24bSC0GyOL844XVesBSchOFG5xOkpg4hfASZiDGZqEo5g9T/UnqEDoy3BCSxEOMkl0EqITG2s3rFBDGrBCj4dHUVvH6zwLbExnu4+mAPpiMD2Pb4oumGsAfd7JT8ZQIobddFjMWmu7uaDYHX3bsyUwdkFYD4pf+4LshpmdWG89nEBY9p1oCLH78eDOVrrF4ZTpgirCLxUoJkcvDNnERG6rjO+DEV3zXBr6OudiRLuaRaZrYnBCt1AmXvzdxRaFGhiyTHr6KXF789miM40y0skwDBDlsaNdCXseDprdg9ZsnDghg9ewIbz0YuKpTb8/wzx53oo1iyoZbneEbHIy8dtXVhMPLo5A4QHn5KAKukJcdz0lQVlHyKdRjovoSafZjTGSW",
                    "RXRoZXJldW0tTXlDcnlwdG86OjA6Omdhczo6MHgyNzQ2ODZjNDdGNDE1NTY1OGY0NUFCYTJFOGMwQkJBZEU2M0JENzdmP/804/CEJErGkXWM8NWqOhzMtFy+uShSrTpd3ZQtYxoXr37vVyGIgIJ0U89qHAkni/Lv/un5GpGfirLUBiAw5aQW4zCzWJTQnqnWmSiaTyfFUKW/4R2ETjgx+JUiORCC+mXjhCLNqZkGD5FS0wI6MTrnqy5NaSQshgr1/UDAc3VFl037QO3o/3FkyoybYdFiUSkxp/ncUXPBfpQwoEIW2KRMarQ67O+39jW4UQfXaq6d/u+RJQxCf2j7dE1f3HkaesZ58Y9SenWsqDd2jXCw2CBdYojs3oiDuFAujou0U/1fJPL05nR9S4hUE94yQx+4UrpgrJ6UHSAvKhx4/JAlCPaO3I0q5Dc4Je2KCmi6yYrOIfAiSHqOue5/1hahGl6WO4nqLBqLZSH1XU8Bwq+NMKsSIRjWa2d5Tw/H+LBKDa4=",
                    "RXRoZXJldW0tTXlDcnlwdG86OjE6OnJhY2U6OjB4NUQ0MTlENTE5YTgzOGEwMDkwQjMzODIwM0UyRDdCNDAxRDgzYzYwOcqSYB8gY3GHD1JukFe1RAHJsbvRmqoI9fQXtKZCX6Bac72ipkPin53wTuPBSvi0zSLvUX5Sbx9twSmWENo1iNVhAWSxoEyphBz1VrzTWi5RioZE22CYe6NYQAbZ8W77ruStSs2fU5vdyTyViI2KcgDn3torHUgR83q4XbYlYRi0ZxdOZhb+TEutm5vfsyLBd+28ZKFkTBzuImdp1dQgyQWCIn5HncsiqBpyoepFL71IR1UJjGMzR/6jxZ4gJL67u/FpJS9MxJHlthYVQnkX1ktvdpPDUcC27uPfnIyR5YyUi61TtXxnzAoeyDh5T6jrB0QJzwgr5skuGyQMRluZbvgtfgJ1o0xJoH29JpjVSas3BZSWI6TN+ZSYkvUe4RZDVMJ1DfYDph5U2/jEu6ZH5jmWKp4tHXI0c7kZXaqj+DZp",
                    "RXRoZXJldW0tTXlDcnlwdG86OjI6OmJyaXNrOjoweDgzMDY2YmI2ZTkxNjFkNjU4MEMwN0YxZDYxOTEzYzhmMjIxQTg5ODLCSPUTV4uRZN3c3Byz7U/VDkosILpPlNmupdy9w1t5CNM51eLPA9BKHj/3gDOUFCD4/ky4NodLBjl+t6tl6QAkHKT6EoC6Gypq7IpsXStaBUHh7t3KerFLldzvJJ3BzfbdYwDGLnuBtmeJgKriy0b0PQmQPLQvVm9HhDKlcmRyVxVFD4UTUvkfZyeuW88GxzgsH2DbnzVMgJK5t1wFVXrqazbgtzAe8D0a870JMkPl7btbvlzaylGYjPkTnTKaPp4H56ocMoTvCxx5b6eFdLk9aoOCnwMknZHwfGvfTgMw2Cc6f7eAr+ZBcTtUgjRuRQ+WfbX8zJgRfTPHoV0P7bzjFcb77ZXEh6ClJGF28A09DoLaAxmHYaGlXyjUOJknGxfBQNFjVIAfAEaTs9mKJ/mdoXkTzZ78DYxIzzgqtk/3hQ==",
                    "RXRoZXJldW0tTXlDcnlwdG86OjM6OnJlc2lzdDo6MHg0YkZkZEFjM2NiZDM2M0Q4RjAxYTEwNDNDOThkMjdFMDZBMWM0RmZkuJFETmSC4ATo70/5sW1U+KPCGr21qLE/15YUPTG3AJnE9Yk5eTPiB7nfVZXOmeCUe1L8oh7t/B/zbGTYYEH/8hLXSb42HiqWsx3IhN0+MIx/yyhJURCsoAO112sp/h5RVmMDyFRuBO9PN3IerAq7zXAPBf2hDt/SW1rMMmzcdPkwjxrHD3uy0ta0dxaUnein6Hf2P2Y/DBCGf6t0bAu4EWzv3F/lzjIbmMYS8I7yqAslgb9lznzh8W3ofo0SPEmBTjuqOTUBLSfCVQyro1TU9cK8ZgHFN4f28EZI1oOl02CQfwflpGlgwmzjSvIiM/JSS+kfDtGMvGH8sKloFoz3UPo1YW8GwCy06gbExO64ZYY0fKas9BIPde6NvZZ4eBZhn85aWB6H1R+bBzmZsw5t2M05XraZT/UQwrYlOsgQ+5o=",
                    "RXRoZXJldW0tTXlDcnlwdG86OjQ6OmFycmFuZ2U6OjB4MTlhNDI3OTQ0QzcxNjdiNEM2M2RCYTY0ZDVEQmIwNTkyOTQ5QjMzMTs2lugy7RLNbXbgPIrgRPMRpApInjjGKByUWx44CtXy7mnfi6jwuB+qmBFpcGeNYO+N2SqXxJQurVC60NZU09Sh5BEkQ2bIlQ0Q0GICC0JjrkGDGm6Zz8rmOf1/RNn4E8tIeIxCVQwX7zvn7W+haewPYw13ykMJ0vNByarndGLJzZtf31pu7c5iaszLeRjC+g8hR7qV6TzUCRj9Uj/D1kUuYcuoOfSbyXepEenzYk6s72B+rCIMNcA4iH1+JbAl2KaarV1jAWszhES+NWAtJEIbRFAiKTyIsWoqsDVbn8IBFwkcn9/13JtungOFmmLn6PgBPiJYyFwmTXHvXHK5BulQlYQFwzIWIrZ/rZCrbiq4EjZYR5TSovbWPjYqtOD38nXHy0f3IhWDbVPcTsN7byAYmwQakxnJIOMx57HX9VF6",
                    "RXRoZXJldW0tTXlDcnlwdG86OjU6OnByZXR0eTo6MHhGQmNlZjQ0OEFENTFBNmJiOUZBODJEODM1YjhDQTAzQUJGMzY3NDg4Sat0xcBsG3KFnU+MJ70XalLz4hYu2/hZ+PsbF2u27vb2tquBLCbyZEUWq5n8sFTKWAwh7xFtChs/jQhLmEVBzrnoTEZ1tbePTlUEa1bPhUBTWpZ7L8SLe1kOQyJiKAjGyUtZH3KfKtz9SkbUmp84ACakf2GLaYlrGuZretRbRixKURopKI72PJJ7v7aLUTU0NiCzTk1WJTe8FVtY8S5xNrNdhfgB5HgRWk/T+T6ouvbSlu+r/RpOCjpsmyTSSrFJyPRKVmCPgrNWrxyx7oTKXHbTlxpfQF6ffi6KMXKgwJQI8xhrI0mBA3dHtjDulWKbIOI2X0mLKdBcw+SwjMfRehYIxRpKz0Lfbr30RHGCvM8GbsmaZu/A7N2gfGBS0pV8sGMDDemZH4+yOVGo7+5zAOUqu6HyQkUImtfOJNGkr5w=",
                    "RXRoZXJldW0tTXlDcnlwdG86OjY6OmZhdGlndWU6OjB4ZTA5NGMxOTcyNzEyMzAzMTY2NTZlQjAyZDQzMGQ3ZjhDZDU5MUE3NqZNQEHuZQtIWbT9luP+1vVEkkqQzFuIo5FyM0IvL3EGKD2CgpLIEVMyGmfrHHJ3Z6K/dsRjRtBSZ/Os3X8DmIstg5Y5zIKOZo71sO2z4EJJl1SsDjRU9ZLICbfTYpmBdqFYl7X5okP8eN+QR4CqstqwmoIu1mcL3kEDElfQprhs131MM3+xHnnzpNHTRjrMrszcuBxuGxnfSFCN4rLUlDqu+wkWnhzx2k+7GGph0NPvrkrjbCCmBHEs6djhWoPSQymzh0DlMlTCLZk+B+30WohwJv/FGH4DrYUozgcv1xoeRD9FOeg3t18dciWZacxbYOYGrJx4vJRKJoATRYYxRfdbatDnmedtN4qS26oG/5qzLyGKdVYqQfOziZoa7g797eIqM9R82kOX0j0En5V9efzLr/p97znLgiCv4o7cWAlI",
                    "RXRoZXJldW0tTXlDcnlwdG86Ojc6Omxhd3N1aXQ6OjB4MWUyNGZjQ0UxY0IwYTBlODE0MUU5ZGU4Qjg1NzA2NzQzOGJEMTk5YdSOp/e1GINQxtPHSzGxNOJfAC/M9qS5R5h5H0AZjPQACOq81nqfXHYcsi8PiILMJWhrUrZUKdjovB6HV0jivK1UvrADdhMU6PyN9NzQwxCq2Tz4+JyURSLBFXXB9LLROIsMhJOj8/+bsR6nrZUMGWTLkRM0X3Wbu3grVWbD7l+O3z5x9a35owGlL4EDBMxeTnsNeH8FQvN080T1SQNdo8nK86lcfwBfai9QICZRWBLie/BTAndaSb03PVRsdjAfbyEXOuzwbvU86vWViI9jnvItxntUDosvInNn+jRXqUgkkfgJBla6bF20dYP+INr6afZn9mTlWHLL7j5nPRfvja2Qhr0pKkqOBGO8o+80QX8DjboN/8nam5Z4QipVP61k8UsRRFStvvEiYCS7lFkNACOJk3TkiWgzJ8YsYtGembrF",
                    "RXRoZXJldW0tTXlDcnlwdG86Ojg6Omd1bjo6MHgyYTYyRjFCNzA1MGRlOEQyNzRBN2E1RTcxMjFGOTMxZmJiOTY5MzEyRQQFCJPXiByeDZpw2h3/X5irFoFg9qDeJEHpmOhPRQP+Qhu+dBT3feZzw0NBeD1ZbCpigaKHyaUPsLKAns2PqAqpv/YVALfXX0Cg78E8Hq7OzuRneYS9L0dObYJE2BfmPBV7y3k61/Vuni7s0jNIoN/91MyOLswa9IWaQrueu8yA/TUkI8BT1+++OyIXL7+lZPD6O4LPpQX9mDU1UpdO/HzN1LKzkL6zc/dtKSHUUCa44rB6VVIEeMZdTYCNxRR5cY1mblly5MUZtDk5l3cKEYOzydU+8F/xUKx3dJZXypktW79hOpR3ipcxJC/hOc9NdsPxXxlqN8S4IeiWGoWDeL907rqwx3f+6fX6R9iKmkeLeO3OQzfNF+Z7oHYi9NlVWNBTAEf0atE3mSkXOfqlbqyek1rKzfr3t12aSsBbOEo=",
                    "RXRoZXJldW0tTXlDcnlwdG86Ojk6Om1vb246OjB4ZUZiM2EzMjU1OWE2NzBhNTBmNzc5MTY5QmVGQjM1NmE4MjQ5MjI3NUOQxV6DzahGYNGiTn3jZKW3jFeT9UUZUDMNsZp3pgEQ92tYSZlJdn9QcF5lJp3V05clAh3OXLkK6100MRd+iZupeQ7/KpFhgX1ahZoRwbNwR2XoHQ/QCQeqPVw8cJD3eSEe0Z1ZWeUXyayC7GOBATFyjn4p4qDdfx7zN1/XBZbFXcGJ/DpJ0BDAld4jfqIIn5+JxOnWW9O70lZVaVzrRG+W3rPZYhw6a9YMdbDkuPdFxBGd4K/pZdifzpqTTjaLbbsu3uqLVAwHsTbAqE8wfxzEGi7qSQIdDWUsTLI0O8R4dabhGfbBdb7L0pH5Qjen8SdFhVlrwfeunfQgpfYZp6WETpnmdzXaBz5Tysvy+1pEDiFmInDwJQ0owWqDrSCbEt4pU1Q70hJOBJvvpxEDulzTlObf7ukDiJUfWzPu+AYY",
                    "U29sYW5hLUV4b2R1czo6MDo6bm9vZGxlOjo0S1RzS1U4VThhcU1TUmNReDZLa2pnOEFUdVJGNHhEbVdjaEh5OEY0R29BS0Q7vPCa1FzG9x5WjXz3FnN3WkH/wWACF2bE8ChXMmiRELuyQW3PFsdOZ3gQ+p6Seexg/8keZvrgpyAqZQ96sRidvHvr5uTUxAh7j7mIgWyPa1suYhXPt64oI1kbHvIDJNlbRq9W3qr1iYH58JjlBo+Up4x0grLa1qqgy3GEC3+lq3TxvehZhmnGsxYwPr0aV3QxVX8WSwHmbLpUuQE/2lwUunjLpU8lFkzh+/ViJZIRLmakJ0qgaeucFMlBKbNYMNBtTaCf0LixSmAySs71FfHE7+wb88wDi1JXzmU3mlq8/Y5cK7vjD/pK00xwZFNpJO4e+cLsFRPMTSMS52AWFqt182BmJex2DxqfKZctltRFjQ8pwa5OZg+Yze8+PCxgA5/+kE3+N21XSretRESr0xh36ST+wr28NGsHXnW9j7F9",
                    "U29sYW5hLUV4b2R1czo6MTo6dml2aWQ6Okc5d1dnNGJFR21yUHZzM0FlNG9xVGlyTmRnczdXcTFvbWkzcXJ4RmFQQ05Wib+FMcarb7dVs+I8YLnrsckNJctjt965NtAcGGdn1yxAn1KugoM7J6NCorvbY6N0cHzomYi3/H/1QlUo5xCY9pXys93/CUEeEEXM9SBFKwbjPkYrj1JtzpQAi/zqVJc0Oa8Bs5tUNmTZuRADfq2M06n8whTKe56kXtw1jgmEF3FahI7uh9S9U0HhRXQQc8ZCIabsgpwrYgVJNoLwLEURYh1QD47zBrxS4RwTrPUFdjkZwngVepPt0I4bIAvmY/iU2KtAOLakcdOousDYLbZPz8uhkePnCGMV+6Fy7HwO4qgVGtQnjLnlPBSaVMXsWtqnyzPpSC4oG4FR29b2c0NiF1OMC9RSpAI5Zp5rZiTCZbprgpzbjMq715N7S0ywHRKlQ2K1d8Fe0olvMG9V+162UWGBChRQL3DX/7UpmEUkc+Q=",
                    "U29sYW5hLUV4b2R1czo6Mjo6ZW1wb3dlcjo6MjVSTFNqVW1VVHBiZkpiRzg4eVNzeHMxQjJEbW42M1BCTmFoYjQyN1JaaDKkZWN92VuJqX5Ifq91xPni+MSrdWWOV1/kGPqj9oByoBbvJl1KUQe67ptK8/0yj4UKpwV8CI6kvUQghEikkFg8bdVnAriLVBsBKTFq9HDm1+ke4zKN5KNMgAoqVxBphrN+E3TJzeGCV5avPln2l4KJ1RgsOomqW5rqXSThtHWC7WeaHLlDaaLjZ28Dzu37FTBfKWH86uy93slyhgM3NcMw5+ldET1e1SCHPTCPBH+ogkg3hPl8eduEwRJe6jj2hiVFbRj6rrNTbTqgqvjprCDql9vY6PMUQSp4JEsEgPVsJvq4CfZsHkag8/LYe0cHN7/2kSIR0nSgkS6I4Wh/ZKkl2AENlcgqBO0HHXuSfMjhTqdoYaad2DREOLbQ+IRpaInCBBca/XU1daOkuT3/+KV+E2eRwhuWdac7Ja5ExuAXzQ==",
                    "U29sYW5hLUV4b2R1czo6Mzo6aG9sZDo6QTJpeVN5VTlvVHVLeVV6SGc0WTNmVjZBbkM4Z0R0QnE4SnZ0NTJUWXVyY2YDEa1VaWoYzpCT8AKwH+YSji2C5OjI59a+si/kcgAr0u4hhlYLo1Ur1RggaGIwMiTpv58C93AGv+fYdNWiYnIDt/nNOAYTJG+D+UyV4gRttH+DZlZBLIC3dDWxPcT6+Av5KnByLVYbtQ2RmaNKvuD9R5f0wbJRGeRLCUYTV307WmY+eGEl5BUiVVYxtCTEPpgbODjoJBZ070LJUzTgnV4saINO5xjdeK8yevblJIcALPkqQlOGaX8WjO933TKYdBZEkLC5gR5jAvpz58lJb3+vJ/y2HzMNoI7j97A/J3/M3nLEOyNc+fz4OO18FrvnsUyRmWAbGGUvMW7WUyojAVJ9yqngdnFT5xbyWss6hbMYHQdKHRwd/PcBrGJD2Ece9oXqGGTgl+c86LqwFR8bVLf5vl4Dp9W+DZ3gEWWzq7d4nQ==",
                    "U29sYW5hLUV4b2R1czo6NDo6ZGVhbDo6Mzh6NEV5ckt1eWtWdmIxUExOcUpCeEVWRkxkcnFkeEJUN1lONTZ1UUFHVXeiQ0aX2OQ+jv/9cwniffTE6WRc4eFEeBrMxzPszahc/MrmHFa2ta8IE/6ybvISYh5Ga0KD+vHhhfEPiPsWQtRPCekVetFbauV2jusNf/ObfoX16jb5j+mSuS55gDRh5BmEqmJzmC0v1nw9vCXCOcCl6tiu+drpNZcYBm4JuRz2KTAPRsv//Z2UgLx1kiErz2vGMsddJOuFLicXp4dyVr96allaiolAkoQ3iNTi3sa0wRhkBBGfjJG0DclmoBjjLyC90qENEmHlHMQqce2D6usuiyV2GE+HG0vaZh5WonEX0J9CYYDNv80A3g682nm/aKDL7UFgKWlmABTmCpCj0q6FvzPiOLvs6t4raksmY9FQx/9Lhk0qJBqc6mb2eWtcKlU7tvtf5fCreb9vv52ew5M/KSvf1yRGLezpAwhAKp7wAw==",
                    "U29sYW5hLUV4b2R1czo6NTo6ZWlnaHQ6OjN6R2p2aGg3QnY5OWJZZVY3Rnd2TjZ1NzgyMkZaUXFwM1Y0NGJzVlloRjg3MhwwkR04B9PJSft3qYr+sB8xX9njtKzmMrVwodoaai1h7jhXElfQwcd9Niu+TPxhgMUyJJ5z+W7Rd/4YZ3ypJlnQTD4BUJPCaqQMByrQ32T4Ylzp+s5WPh6dL2a0dPLZaAL51SsWGo8Ml+c5NzBqaNZHA+bqanE90lq0Jhh3EcPVZDbXRRybAW3GOynWBpkHyV9TG2fNDDkMbUCPsMMxNRA43fcutDSrbB5WvdOJmAsl99cNGfMfayUZJ8mCyNFIR9isNvF0Ipw3Hoz7PZHYLQNlnjy4InbZZzZzVHzA9xPu8FOQvF50uuwVEAdX8o/ZWfHW7EHgAdweadauwgQgyn+5+krJg8uEEMIErX+HZnvs5v5gMEmyyAez3hDPddyZtcJ+n9OSSneTwNO03IVxwJqLzfyVpPW54l2MG6WD9K4=",
                    "U29sYW5hLUV4b2R1czo6Njo6dGhyb3c6OjNaclNWSmVYRlNEMnV0Nzhrdnk5OXZudVZDY0ZQNmdxY3BLUWlDUHlGaVBCSmPjAhUDiKqfZZC/1ETbMUa40PentAT5bq/SDUCsdJaW0fWB2Wl1YjD0C1kn9Ui4A8baYJRi2bMGkgsVlSJJrIpXE1FGb9V/vIrioaFFNziJA6QwyAT7AmDKBVj6mgFSj4Z81uZFeBYonQZunmCyFFUNyOvPxglATq3UkJNNk5C1EmOB02A90Km+e7FLshVGUzhMeXGSypZcyxHtKTidIQkErmBwab4V2dkfRdunK5GcaO8gEuLqqDr8LANElqy7CiKQy9EzxXEmjV5VQRw+UIiDjfd7GBCfWqr+sNOeiVhQ5hgnjSqgxYGQrb0BwvtnyB/9jGUdOQ97jXUnDfRdl5ueu8w9HTiYSYJrbK49jFe9jRWTGTJD8SPUs7G3AINnyl0RZDmjOpzL4ie1ObUi12+24qe0TTtoHCnL+a2FTJ4=",
                    "U29sYW5hLUV4b2R1czo6Nzo6cG90dGVyeTo6SGlFQzNmdkVITUZyU1l6eWQ4UjFlVzJuNEptMktRMmdqZlFGMzJKcEFydktnlyW0J8jGFHMI/5OiYafjyMCOHc/5IZ67oCDiyzxKQyFsT6IGBKhIMmYAlzAzxj9ONg+JlHiUKRHgurHGqwNieuhCkmCE8pgk7ygKa9fXoH2FW3qCKImHqFxPHakaVqXcDmT1u4jK2oP1E0KZ+e6XkjefCctMyx4S4JXn1OE3cC8FU2+my4CV+AKktDCP13ddoEFDGpj3Ql7VNRSM5v81uVC4uj3pzsSsk4OcRZHA99EvlOnX08XzoK0TbeN/Q8C2dZ7NXssjBSQUjRXaLhHWxHmOT9RdbF8UB9BY7QNUCE39B+qpoTHPynOGcTzy4RkQagggAgX4nl420BrbLqUCDJ7s9JEc5qoUF7j/s+V4BoZiDwFrjxaVqXXJFE90LruoZH0ezHrUIy91FneZKH9tUjGO7E176391bMde6oBCAg==",
                    "U29sYW5hLUV4b2R1czo6ODo6YWRqdXN0OjpIV0RkVWFUMjJXaU5oU1N0M2t1S1VKbUVLQ2dVYllVN1ZBZkw5NkVWc2N5dqiPGxtUlGa73vzg6kXaKbbcT/hV6S+47GPpCw9cHXegUzHeJNqIwP3ZJdKFzmThlaQ8jO4ZzRJEH/SjBwdU3K4lJsrHM/Utx5dsFCrorQ+GS3IUO+zsEKtBiIkbPwUJ3FXVqgqfumWxK3a9s+px66x7QrY0r0BZ+jg0Ubzs8k/1RFPHN8cqxyJOgegiBSjw+cwp+0zc+6aJmFxSbNVOdwQC4oluuzoHWTU/IlZgb02oZZXRa6XGNrVw1D1HK6a4aEj4oIoYCE2lbIl1ZH7EvPsuCMQi32cU/lUrSZnCgocQRuByFsHtuCEzGEbGKfRqlhPLPt/4RtUtBQu50Q9wqythqWbIVGKp2PsM3NKae6+j+IC7PyB4GKpohmwZaQh1UQ8EInta9yk5BbIDiurDmEhMLCTgU/FBJuiu3iwzGAhE",
                    "U29sYW5hLUV4b2R1czo6OTo6ZGF5OjpydVRzUDhReWZ3R3dLRVZ1U21rWm1EeXlES3ZmN3o1WUVnNkJIS2hIZjZznkiuPYng48TknwTVn6wYLD9MavC5vYwy4jd1rQxFKVWmh9NMrHxY2D0/rwUNs2L4Hy7jbpnsP7U9Ua0OVFoc4j0ibAAKmOwqwHqPliEXPghut9YIHiMNCq8iPfw9vrkzePRVtJLIfUfP4XWPdcXSlSWO+4TyzCdKCKmMkvJFGnRkojf9l2aANwSKS2QRFbAkpmKPfVAezDWpYq8iOKkLLrHuVKTKlHc2RuZNqR3Pgx3CkIIrfyBI5+uksKGR/TlFwxRJM7cnDuRCemLqJBHQUlSi8tp5fHq9kEPEwfaxDbhb69qqk6f73MHKPJ+yfah7IKpr6g11td6HxvyITiH9Of7FrKZFM3EICTGhlVpfHk81x1qfxTnzMLEu4YbTdn75ffxuLU2dptiaOqEBF0XkgQYp1J0vW6ZGwm8MABYGsuo=",
                    "U3VpLUF0b21pYzo6MDo6bGVpc3VyZTo6MHhjZmI3MDZjNzNkOTNkZWFhNmZiNTQ0ZjIxM2Y4YzAxM2M4NThmODAzZjFhN2EyYTQxYTMwMjEyYWFlNGNmMjQwoF8Vcwz2z1s35OaWmqJWlcsh1SOmCIcbK2K4N0XK4dgSzMbXukPkDVOcHNfrK2NBis54zgAAsgaiqD8R7Hq9l/Xh0ix7uL76c1hCAmf7+6C67Fg4RKuhUgoXIIR/sHYGGb1VFFd0lNWEwy99mrJsR1jKIvUq/hbRjxq7483TfJXhC0Ecfb8pxV0kBwsKWEBQRKX5shtWc8O1+NLwPiiEu4dbUdSqLrP9u1/WlsOrfOjfErBRd5NTzM/8Ln9DXIqJ5Uxfr9RyYzYyHZjhHKyi62RJFOuSRXSs6Sjwv+u7X78+OAFYvnUg3uMN9YVVro1ymklM1auhEeN2pQtLAR+8VKTUlhS1Mzle3nbfKtkZm1qYjvyhlZiUkLRt76DzsnvRWTSwWV/kkgXhXQo3dLMh09Jg62fRZSyt7QBGWYc4YxQ=",
                    "U3VpLUF0b21pYzo6MTo6cGF2ZTo6MHgxZTBkNzI5NTFjMjk0OGJhZGUzOWZhMGE4OGQzMmIxNGQyZDI0MmU3ZmQ1OWY4Mjg4YWU3ZDkzODlkZDIyNDY4bO0dkvCMTS2fP3f79fGaPrMG+vd8kyRKHOn65SeCvddIc8Fcx47y6bUunFnUDMXLwjfon3sXza60QF8llhabL379HeXQIfUlNfRmmiBRrEiylvQGSMHDEeAOqMV1g+TsOd7lKfuQA+o3bMGMP6E6GZ+3w+35Qop/h1Toi1+XYOMKPGVfRTstFP3/8YaZhd4KO/jHgOUQO+eeTRbVhQT0C1WSKLwcNEZfcxHwplzR0/uXGNL6mBaDZpv6PlSIkfXP3UHOKIXYROlOXjI7nZGhj6OzW9P7KTX1zQ0KR99pNpyyuTR5FLzCtIGBnrgob5oLaxFbMBgtVhVP+kBNLK1UNJDTQ7z5EvBqY9fnZ0fPq5ky3RU04X5hHR59Oh4iLowHUZXFTx5TVjdhGGBPsJ4g9mjKKXS1L++52GuovmxKLk4=",
                    "U3VpLUF0b21pYzo6Mjo6Y2FyZ286OjB4NmI3YWRkYzZhYmI0ZTcxMGFhMTNjYmI2OTEwYTIxMjQ3ODIwMzE4OTg3NjViMDU0YTM5NDUwNzI2NGI3OWM5NcPtyGarW1+ZDLsvOyHlJ0raM+oAI7vP27VLEWmXmi03FD+oVQpjEZKbMSUkt9gcqtJVHSr7V4gnpgVuuw5Nc5IpDX0WVp+bddFrEijO2e++TA6X8W1kh4ESt39EC/e4W8ORCvAR+lKke2ZbLRT/z+yPrMcpduB6ag/xoGxCUhWbt15vsOMCr8nQYvgBGoCcBGPcK/BNfB1atWH8bBF4DzFAA/hvqsJ+Zdxiicik0HWmbVpTfpJLxOMy08Ulflle6X5bAExSjKwkdn2epPaeftRmB+F2kDCodD42SOUeob33sfIgIJwV7hCJPrEJWsH5QAWCRawj8txDMtoppJL6sW7KyVpRUqH+5sPyB8qsYwYcmS661OeO28ck8JEUuHd/rtyUGC1Xn7wbbNhjhEB+JZLeSxpq863sktuXSN+zbqBZ",
                    "U3VpLUF0b21pYzo6Mzo6aGF6YXJkOjoweGUzMzFkNjEzODc3OGY3MWJlZWMwNjlkOTcxNjZmMzhjZDIyYTBkZDNlNTg0MmI2MzRjYWQwMmFlOWQwZDU2MjUVVgRa9sFmQMgS08fbciVpGjZUNQh2s7NpE0cuwLPTrmln07TcamxvjmhxoRRE3Qdi3UUrEHkOYDq6S60JcwGcjCqgCTrD433JQd6Q/coxcw+sCjAWPXc+KfnQ+RR4F/3r6G9wNyNNjV/KmvX6TeMErEPy8yv8gHQ7Bizydga4+yrR3OU8kGW2pLt1tmoaYTS3JjkJVOoBFG061dVw/kRK+ffj4lKJ5Iog3vhBF+PVncFleQe5ZzxZ/oZHeCKdB9Ov2Fh4vliKjRVVdfA+75MpBQa8MrZSXG7zQWL8fYTn2hcSQABiOicBQ/z/ZT4CKv0Ta0VtqGzBoaGuHUpTVNUp4HzWVhYFxammDHCJxKOAOJ1UgMcELGxm8W520RQUyN3FTiIz26REz31Cxk+OT+MjuHO5Drvr2FsIKM0as782pA==",
                    "U3VpLUF0b21pYzo6NDo6aW1wdWxzZTo6MHg1YzNmMjUwMjNlYmI5YjI2MjhhZThmMWUzMWNmYWY2MWM5NjM3MjBjNzE3ZWZmZmRlYThhOWQ0YzBmOTcwNjcwsTj27SRc0ISWbTwAcnjAxxbBweo5UoOCR8bpA/ZB2YnXk3B8COr0/R7I5jHOh8xHoQbr0Vy3NP44l1WasuEHnrklSekDgYYrVEaIG2xkfVmJsftJbWhAGJrDbxhuvrIVb41GpvtzX238fpJzk0NSE1HCCdaLuXrkwXa540tMx6BSw8Bm7LGWJvk9tlAHQO/UzdDOeKULPLOEHLP854LaDT/Ma3lqrzD0tpezQbdIpGbv/eQHDr01cMG+pYcujgHWF55Bofz1UBhWFEU/0tnpJTTdOodhW/SpC9QLRNQP3lSNi6DBq4+JTI4cSKOk4a8lz9wUTYN+tjtN0emBysUhqFqZMUH1Oh/J9UXYgipuyS/HeT+KdjCISgDizBjugA+EPsrJc2on/cWZdWAIAOCQ+2ZyfiAPF1edRnYFjKJB5sc=",
                    "U3VpLUF0b21pYzo6NTo6d29vZDo6MHg0NWNhYTA3NTFlODc5ZWUzNzY3YzNkNWJhODRlZWMzZWVkYTNmMDNlNDgwNmFhYmMxOWI4YWRhZjIxNTQ5ZDM2QWLuCh52A2QKr2e2j09N6O4F8TSqsgPHiJVGN6W59q1NbGPngK4cMlQcJsnp9V6GHp1/Ppzmq1+LCCPtjhgf7aYiaStU/LMU+P7kNiyHCz8ZbrpDORW3xD4jdtc1ME7qmlGtRsczVs/TDsQ20WEP8q8usM/BcrL+ZP7Bb+lKLj4ZSmoVAt0a2pvXGwt3pbBYVWrWmRokpIWBYMgBUXXRbXoidbD7vESQXiB8btGTOPDW4q4MgBkGM7y1gQKKwKiNU4aMdyhEyiJcxB/iCSQcmK15d+9zqZEQ3ni6jJhmr0cFSbYcxbGs82USzVRwoHj88j8gzoKqaFsigzBFJGK6Qy2AE4Xsp2rjf1g9NVHS4JDGtnyGZY3+wfjFOECqSRyfM+STJKZ0iRxPSkt0x71lZPMYqY33YQrXeohjDqRll8U=",
                    "U3VpLUF0b21pYzo6Njo6cHVzaDo6MHhiZGZlODQ4NWY2YjAwMmY0MzMzMDE3NmE4MmQyZDIyOWRlYzZkNTk4ZmRlN2QxNWRhNDEyYzkxZmEzZjE5Zjdlt/eLAQH+NogzW3Z55+IEgDKLlh+rwb/2N1ojt0uCS58aJalY/nqvGH3CfNuw72FnT9uBJgxOAuaPO9VzbdwRfWbXPmhR6nMFGdOyxJb2bXrn8yE6hFGy8hfSm8xQZ6qfDw1xmvAV0Et1nyOEZ7v1uAO+NUW9Zakms7rVQLaUt9gP93HEP3/3cbc1q/Oggzgo7XczhFtRMiPlL4UVXK4dKYtUkscHzYcO/+iv5NxbcJHn8zt+pHsmCgfHWNgXi45617K2ZjcF8SBW81nJdVX5FSF4G+cgFJOLhoElF/qxCaowmZDt5Wuz6MYKGe5BMHPCGB5YrYPGj3FfE1XrRDjyRmWewz+fkDXlL7qANbHwrSqgse0Xq8l7keGvy9mcOCFGWrLA+aKaV5E7Eqdlei70Qc19toQQeYyYOQZHR0NXSsI=",
                    "U3VpLUF0b21pYzo6Nzo6cXVvdGU6OjB4MGZiYjY2MmU3MzJkYTE1MzczMjA4ZDFjOTk3MzA5MWVhYzg2NGU2ZWE3YjJmMGQwZjgwYjY2ZWM1YzFhNjFhYg3PRWLSdMDLsRCCXXLLFPyNNYE7o6YcBB/fl2MjtmpfhvKqJmGfRGR7eWqJ8sz0kuhuJxnzNF6XHlnvGcBdghbyag2QPjEm29uhnpE+oQUV6JAyWQA9sPiTNIUmj0s/J6SN8xntdmXNdoPqbx3rEmh91jpgQesSbgStvjZ1kxDEvfV0eAjfMAtPzx/Qu4Dh/xHaDsYBbJEk/XrJ+2AfC0KPqaGzMOrQsecvS6Ay88jip1bS1LOYEnlXKLAtY4b3n7EIawLquqjpb6tHJftrLsuuK4nNUTnkpoHATvcGBa5EJxiBXSsEe8jUni/rYXMqSeRIsrM8Yxy+ANYVcwF2o8zGbn+iWHkeZcEGzHu7vu2xKL0Q5QK+3SePPaJH1PpN3FfZVHYEOKXKwlHdF5mefSUG7J6DWIJcNEW9kZaOo7it",
                    "U3VpLUF0b21pYzo6ODo6YW5nZXI6OjB4MDZjOThlMzcwNzM2Y2I4NzkzMzZlMWRlZTQyN2MwYWIwZjM0NjQ0NTZlMzk2MTNmYzQ2M2JhOWRiY2MxNGU0NUwo/1sWDeb41qKZr0T5B//89kOlmIOtxCt4te6p4ObQmXV/Rjd/xyDFTZGpGIDj9NFEK04SJz3iMz/AGqSYaFy9OTrBfFdrAhx/UZEeRo3dLZ3ZMQV21eb+RQURGMlemNXqhwfUhl7paaKHP1qQ8drE91NjJVG9BWe6NR8ERv6OfirnZdgF8xvjKrzeVnzCxNtpdbwtAd0u4IY/ID8Rg7EOIyVjiZTl3jm7vu8d0YC7l4+978MiObjm3j+TOWk+Yfa0F07oATxdgzl1hrI6/a5J+vC9FeWy5af9WbXnohqPXuRJxv4LxqKShi3GHhfhI8vo/2tVtB8jBIPFmJhK6N/ceW6cSmOM5pOzevm22/tWMQ1lY5+gJpVcG8c0sr81Azi9jGr2NNx/r+cuhcI0dHcZP6ibw1vR8LesNY1Ha0vW",
                    "U3VpLUF0b21pYzo6OTo6Y2xlYW46OjB4Y2U3ZjI2ZGE2M2JmYjVlNzc0OWNhZTdlMTZkMzAyZmJlMGM0ODI0YTQ4MTY0YmY3NzU3YWMzMmE4ODkwYjNhZR0F0CK6BUHiIW8no2iJEhtphBBFPleM5CQF90FZp0QCM++ynLR4XBzzyr7CgRvub5s08ahtoSDGUVsa3sJYJXEXkgJXByv33082SVd6Z5n08PQU34WI3gq9ICB1ZSieM7bqTCjX66TcsvF6m/Ztfm9iiXT9JInXLDt4hrUD3kBqewdQs7AiQZcQ9JT0NSSlQxO8s2GRuwndqXO5HBB1rMyM1XfjpPEWSJ/V4dFPR6m4eYyk5mrc0BtNgi0E+Yku5AdxzoU/krFVmX1uRfM7Ug/Y6vHMiPQ9x6ORpVJ4MPDU64QnHiS+Ra7vXVho1Hr8y7TwLMETgIoxhnPVw1Edauo1+TGS7ABOORJVTCECFsDzsRBiy8T+aAyWhnrRmQtoDSE883d/aUpQHZHNWKvf0fYEFWoAuDEgdWC3BrZ72yKR",
                    "QXZheC1FeG9kdXM6OjA6OmNyYXp5OjoweDZjODY5RjVkODI0NzZFODMyM0RlZTlkM2VjNjAzOUFlNjQ1RGU1MTAx5Hj+afRCqemKWtCD5UkZ5oPq3BY1KGHhwAkNrIgyuw//Ofeokl8Vz4ouAkqDGk+7AhctiRIM+XXk7A2TcfdwlqGezIjqFHRdbzgNhsgQOKZjW59kgjDUEQK1h4WVZ3Nn1iZuy6qC0GzwJIQQWovNv1/kia8q0sutYbke6PX7SbKEVskR9HcigYFpub1C9dm7DAt5CGSYwSvhISgGygfXa+2V5Hzi1FdOQc1BkcwxCwxCpCuOB1IJdccZdbH+NhHZfhJYB3dfEpJ3EOZyiREnrGMx4nO+VISExprtA5pqHUdz3CzgPQ382/Vf3JRML4Vouy7nAy1v702/n0U0zmI8/VZHAaNn6GbGTePHhxHtOs9ufOSoJhbWZP0T5r8MYDUneNMUJbPqlSHGCQK7rlTFeWyJ0+mOX3++tPp0GZvDbA==",
                    "QXZheC1FeG9kdXM6OjE6OmZldzo6MHhhNENmMEEwODZDRGY2NDg1NThBYjVFYUI5QkM0ZDJiMEU2N0IyMjVBnNW6vK31Adlj0hLbJIGMG5dC3XizJbAzlj2L+1iJAZY2ImtAQ36/BK21v0MXD6BnTg+Dp1+gcWZn6ekiaN5acLXUeK1fe+tQvyWEmMK7iyzMrLp5ZXTziqntMUaEoMhwxrzOLX/sSVebEL42/lLYR5T06slgAlFNDag9QQYVJpr+7GJWjHg5LwY24cdDByjv9oQhKIbZ0Fg6ASp6mtLT7BmN1Fd+qnFqhH6ZkrrT2Ns/ipPswEtlTR/w94hPza5/xHzHwDxQIi4AXu2g/K5U3LoJIT+h/vV/BgYvPh8B8oTcMDQylQ2bR1AYOl5wn4VV2yUC9sj2gHrqKPFsLxTVU2oVoh1VDI39gV48LPneWO7QrGLtwhosVcpfx0J1nUAtin6bemoLA1veK7FZerZxz3G2Zh+1R2uWUsXQyf7H+lY=",
                    "QXZheC1FeG9kdXM6OjI6OnRleHQ6OjB4NjY3MGNjOERDNTI2Yjk2ZEUzQzMwMWQ4NDg4ODViODFhMDY2MzA1RHv4Lnj4ghCG+ZjYL+M+sPry6IbPbHszOPd/RF89Xku3VvV8X4eVR0RP2GSM4i1k1rPd9anQpFWpmEJWC2bA8RjGvaAvDw20DeW19nFFhgIIiIxzZjEuL+l3IvzGC6sSQd5D9WEZsGp3uj1fBMMlAd92HVr4C08KgIZPSLGKYu2meu3LHjLm4e0JrG7FeN13iP+JW9PDxdKmCPYCqtzSlPvGUKNu59gaWXzaycK/Zxp0/iG6ZvKb7M88g0FVQBIUboNx7vYZuO7XkxCyVyVlZPq0Ni09ih1/Fy96nnbFDrrTqAeizAfqB+KPAI0Z97EX/08oavVjq0fEfY/NvB2+dI9SVyGA53Vmf19VGuKqtiXZiEnjLO9mtEz7XjVNWiYClVP3yEhbZEGBXSDRN15T2iyQWzOAo1PeG3j71q0ZJsSy",
                    "QXZheC1FeG9kdXM6OjM6OnNjZW5lOjoweGUyMjU4MDkyNDAzOGFmMDgyQjdjODM4RjQxMzFFRTMyZjFENTdFNTdb+UtGiHcfIq+VJxEUKI8bspn937nZRHeBHz7Yb/pa12as36jbAYDzXDz4PXDiz8OmCiMPYyz1QEFb32FXLstutBu/HD0rtz4BmTSlBD0ae5F1d1RVLKouGGzp7hekB4s0SPkDhFnD7apFoQ5mrSE3hoduIP5CE95Bza/QlybBrw8xDomJA1HRmsIo7cb5xjDBuwTKJYu+1U1u5wk7CCWZjJ2Nq9nQhC64NcYbZ8FKA69XShbzMzs+nsNIbzsbOU+g9BPO9VjbOCXPBRes+ROoFnVuCCm4FG4NlrJHaoE19LzTgSXWte6P+kF1MGF40c+IZr2qAUqneFI0YWPKawo3uiXL2/H46cfSMjCq0Cx8dGI3BnOhAztCpSCtTxNhNaQe0se8X3G0Tjd05ecXuHxR6Y47VPeojWCEsJNwM7JM7Q==",
                    "QXZheC1FeG9kdXM6OjQ6Omdpcmw6OjB4YmMwQzZBMDdDNUMxOTUyNDkzMUREYjU4MzJiMTJEZTEwNzE1YmIxQ8AORVr4scuzkEe81Or67TO9M6DRaNsV0je+3Bw+WCcB4f0Re1Awmre8lq2OJgeXFGPPVPY/GBjFL20WISNJFtOT0WYJ3XUQOKXInRQo7PQXGXv6SuMVbTV+rD2HcdIjannF04egLPPzwCe/Jd9M6kNNaVTVl42i3TkcKY1me79s5vuFwtVryB1U0jJhpIRugS2yP7KtOVaAYIz8/DicEyPCcqrwqOHlJR1o6TUF7I63FOl0qy3TDmcNoHAOwmMmw545RfpU2nh187oVSu+MlHxRgXXrkSc26UjMHoEUI9LOPfzcauUCjOWPsi+d6vo4jq/REkLgvrZU9NTMI1/K9FHm7VcnPngnKYjyUVQ7tx+KFeN5EwgaVdNtxmTpUvA4bymTkBpvGMrrUpGYD6M7bAshkIfP6EEGXpwtfu87KDXi",
                    "QXZheC1FeG9kdXM6OjU6OmxpemFyZDo6MHg3ODZBZTg4MGMwREE3YTNjMjZhRTU0MmMxQUJEMUE1ZDY5MThmMzJFXvkUSKMZOez+djD7oAvSIMPv+8g7LfR3fxj25q8lMUCVyKyPf3m7hqDiIdb3nv5IpFYjDWQzEqijaogEQXeEnjyp5YZTGE9RKflRrRyrkhucZ3DUFs23wNAhTXx3jXU25nWPXUJcLNU29QPG9cS4FOk4NTVRQpvIgkW9cGd6deXtecJwuf96Ty59Yrd0shA17K2ttqt6M8e3FdBhWRPQmPJFxuKOx5l2tzlC2wsKzGFQi29zQl0m+Sw8yLeaAb0KnAhxln/r3laTu1N4AIdcRcnyiKMWSpJepaD98JIeju+HrT+vSEZxp6djxUuArbDcagWixPwBlGZm06K4Kl2JWA7F7EmnPayD6DNLxhNNbZ4cLVlM59rtajtmPXKMjNLjQ2h3xzmBYHolpwc4+35hmq9r+WVoIhHN06oFuN8Vqm8=",
                    "QXZheC1FeG9kdXM6OjY6OnJpb3Q6OjB4NTRjZWM2Y2FGNDFFODdGMjU4NTQ3OUY0MGNCNjlmOTk4MTNGNTY5MCkueVQDeq4DSYJjrjJJK9ngVeQZX/7HRpy9TkJbs/2slk1baHsIy74GV8KpV9esoWOVzXqiWenJ/aBX7nF4wMSOE7LrQsW1kZSu/DjUQJPtcCXrcEhLO/9vkcXrmR7ozn6QwJryo4NjonYjh7EgTfyoMoIJmq1wkFp5crblClJhRa7sTAbMgI+OmPN7xljYoOqUZlDlWDS5H+7UMTSZ9py0L5iQpXEGTe5sC2X0N1SZipy1Q/3D3xyrPfrx5pxNv/hUFaJQHdK7peEsrIns6amVk3kSiamYXp2vHRc3ugSq8xYlLXO5OQz/fvqBBDFjTMVkGeYXQ75TmcsgdlAsgdT031/8VzIF4puLG/XVy3iSet4ImbIV3L3E4wrmifr+LO4iy2GpDAQ226Wy9B/Q6E3VAK3rHGbrztr/R1KDWQhr",
                    "QXZheC1FeG9kdXM6Ojc6OnN0cmVldDo6MHg2NDM1NTVFOGVBQzZDRDlBNUMwMjMzMTZiQjYxMDZERkQyNTkyRjU4ApYIO5xH7P86xLLHa924Lai+cDgbFpU589FNE2wFATz/wczPuijkF9XAgGlGNFSd35AlqwHVVZD4Oi1Qik0Jwlxla0re3jPTVwqO+DL3+40q05nh4MJU1t9al1Ylj/xqgi+5CSEwbcqhYPT5xpSG7E43Yuab5dg9okcagk5/wwBRBSTU4hmg0XdppR6LJPT44ZMPnAOohfDfUeN3CPtRUo1gWH/M4Du2Sxww9e3LhSaxzxktOgI3Co9C6IOaBObYd7+YgaMaxpqDff1Or/AsdzhPKTQP7S6jUFDIVAHEJZOApJoEKkzxNQKbthSNh51EnxiYqyeHlRWmzePHwoOGsLFrZiTJy4bKAUnLpZKbZzOW46eiW8HXzeFl1j/QnJuB3bCHKUFEMxaecb8GqL8rJ8Ck7rmIHVt7zjRBELr77Ss=",
                    "QXZheC1FeG9kdXM6Ojg6OnRvcGljOjoweDZiODY1ODZkMTYzN0FmOTI5MzQ5ZjE0M0U0OTFDMEQ5MDZFMTgxRDb1QOLsfU4vicoxmlT0xb3P4UaJiLYowiGK+pEWBjXFx5DwuDE/T+gAFd0qIr+4BYYRtuUJf3ynC1wd3x8UKgSQ+GkhlXeMpaRrjfig1ytju+bdCV8ZECQZEY8BKKGmKyIsP4HBoHRYgveU4KDMjRIkQ7qa4sNcRkcBLbcZz6wA/VEk2biXnOsfabPTuEPmpDZGrfl1dWOtLRMCYnWYbh5VdxsZ3QAaatwdOxEgsutKmCYm8X9kLAvQCogzsCWDPlU0C1Ww5sMFY/SgAzvE5/PuoCQzOp0bpANtwz4DKb5dVp73bMHTYliD7y2NWGchV2SrUtqpvYfYiiUJEqhq7T72DsvhB6RAeCp32azhUR9bitnWAh7Cwtpfu9qL/Bq5gBuRwYOfIyVGOwCU6EtPEuxAgglcewQXgrCjy2dYazzquA==",
                    "QXZheC1FeG9kdXM6Ojk6OmV4Y2l0ZTo6MHg4MmU1MTgyMjkyRjc1Mzk3ZmFCZDc4RDMwMzEwQjZjYzA4OGY0NENFM52vDUXViwBqLg8NaluAxWHMfY3ixJHELlfKeNexVidhaFnfiS2Y3acHSNidqdo+lOgpMW3tQjv0SpJI7EteBbkfeNtFAuYSy95V+hUgslmjNTn3l80xbFouMh2v7XfK7apye55SDtBWA5E1vsnCrxsn06TlONOdALNmn/lB932u+9Sj/JqYSgEpaMCg6wk9JGyxYGMUV+vh/9dzwYOc4jZef/FSmM3vef8tiBF6u6Ic9X7sGuqqqxn78eJBLbQabYPo762pwtp7yblYlRWPxGh37/SN3koSkWul+z6K1CltGpXmYSRrAJ5pSHd2JDxXCvXe6rgJwJ+2BvXU7FfX4GJ61CPBOCV2rb81YYgKE/RWrdOjBfxPjR57szsI7clUHBWVQoavRavSdKzLbb/vPE6knEvc7CcL/sgBmg4PXfc=",
                    "RG9nZS1FeG9kdXM6OjA6OmRyaXA6OkRQdkE1eTFkcUQ3dVJoZFV1Q2lBbXBCOWVqYTdnMmhpNndzu1d+wl/B0N4Suaazu/Dod1jMXplaJ4bGrBPWdxTXg7vGCgfshxPVaaCj4dhambLmfmzwPN2zCBYqXaeu7ZSe8AHmCVsVzPYDcEvyEfXAdujo+hPUL5m57LQ1/5NeAUU23qjO9er3kXisgoLajUra+ZRK+S0FvlK8ZM5LM7aOmjIR7+bT7Q4FQdOWfoWinaZiSKPg6GX2PqXJzDr4QTLuKStW43sWxHo9hYxzFqBe7CBAI2Ntxot6FWFRlsmYd/4RZPtE03Vmu/j/tYR2icVHOhaK6o3DxO98ucKg6Y/EFOe+ROsDxntSNQpwyEaeoYioVQXEbrONl+AfF3B2NeWjfENXtIY5PTyhq1HT5M3lW7FRwntpYF3b0EiDogqopn5YpjrzP4znB5z9Q9V17Etf1CGcaYbn3csP09KolV/myQ==",
                    "RG9nZS1FeG9kdXM6OjE6OmV4aXQ6OkRCVUFqVm5hcHNiUFJUNmQ4blRmQldxOFNacmpWWlhnQnC+5eGM19+efwzhtfvbnz3yJqcy4jb5ZgZdTBiV3bUf7d+DYHlL3e+fv1cTU6Fzdt8euUndUsVnNvcnyASRPDmaQRFoAZhBmf5yIUYSe5qtl0Qe6PQ+bXQJhpxKC3UMOwM6PsP35RDRBJOhEZ3Lk14SOjIbV5jAdYVnGubaRqUNEeQEw8Hxl9XdsC8MJ0sl2zLORA7BnW9ILQlkkCRl1AlYeeflCE5BG0JrI0lmPIC+moB7wLWa0yCpBNvTmMA+LB8gGTLWQgTPuE3VLvfodMSkXp5TSyCM+d7c0TwzGS4BFVbK44B1AsLdQz+OAZd6/gSzEFqEekoHooBNJLgi+DyJJzXpp4Z6DWU82yWT4s0Vdxy2s49MwMhX+lgfg0yhkqMkfbu4DOFaE1w4VHyrK8Hp897oiWyMI7cnSDzyAsSDmw==",
                    "RG9nZS1FeG9kdXM6OjI6OmVsaXRlOjpERlZudDhySE11TEU2cmhNaGVLcWJ2Q3hEZHZnN0d6OWJCd4au+6Kflt/j4Q6TlBbtCaq/z9i3wM3y0Yybu67WZOKan+vSnGZ8YmudDCgzUTyrRH4c9+zSC1SJ71B2EhQxCHPnF88MnkXbkO+DWCNoQpFeS55fIRsKvjBn778MppjN5tgg0x9lXULXeBZApF9Run4cese2kkTmOWv8i3hJxmHkYjfsENzuGEsCmRcIaSjDQCzoooBsY5RR7h1Y+eQYZVQTPgdyLPfcnvf2jvGtm7vJIdVsB34zwyajS8ICiQsduTR5RtM0m0IDKK/HqR16sn+3Rb62HKexqj3emWgiiKDcQJ2NT77STElwQJ8gxHy82mSYlQZ2AwoN9ZH8Cl204+HkALwy7IdU4haKSDvukdCy0DKO9q9po3RVDpkR3gDC+uDOjg+F/95xYXRr001zbKx4cmyKEtsvKWa1ceTPNbs=",
                    "RG9nZS1FeG9kdXM6OjM6OmJyYXZlOjpEVUE1cUZXRlBBU1NKc2lHVVhrVXMyN0RNOU5ERHQ1ZGdqXNmQmDAVtagPfS2l8ovgkzBkBlzxA8rC4LqLk73HKThpdCMvSMLgdbKuvzZDmm/ewT2zBr5TYpq9wEMn2j2E3QI5x8wkcKAfVJVYnwc/clN5R9orBWUUfjBBPbD01036+tNP2r+jdul3o5YoJRu2kQMeo7zjtS5pYq7eQ1//W1G7yBvXKlohNMAv8T9YkxuZaSfIROouwu0n2iAu52/bKUjhpryoQn0yBIdvl4LO08RusA2R1s5LJ6K7xzlgtudW/G2Jk3s1GUp5hr2y7Azwr6D5BbtWjYDMhHrkovfCWxcNIsYCU4kuZsJZWOg0DxoC/zREbAYy8/+gRbVIkd2XARVTTyw6gqzzmIDa2XYt4HnAhqBQI6NbZqwEcn64lLEA8xTPQzkQn+mQXLDLdN2e7gGRT4qvObtVRRCxIWNo0g8=",
                    "RG9nZS1FeG9kdXM6OjQ6Omhvcm46OkRTemljZEJFWXhZaFJRTDVRNDcxOFRQd3I0SHRkTVVMWlA37zwVQxaTKSEwwFpkZBfZXUjDFJQUJxGeVDQCa/AZVpB2MtzfpsPHYjL71ogdZ3TQWg4PHkMAKldtsYw3AtAyZT78in3sFrYfQIK9ccJhIrUzH8gawkk745Tp2YwSTkYiOCtuSaowmi/+gph98FP5TAeSF4+0Mu86NbcJajENF/sfk9fmjZ0Gps4w0H2oLOiJRxI5qYe600eRt5NqtK6p9s3iOFrqZMj7BUo8nraU2TPT1wEaKbS2i6g9H447JZlypqO5/Iz3UyHJLcSu10BKqfRJZlTrC+NORnH756w+0EvBfjq3lfdHhkCQTsE3QZD7aTql2LSxK9xrM0idLG+Tte8RzApYVovK8HEHwQE+Cjso9/ohDYihRy0jMMFwl93TOgNvIUZaZMHrWwWz8FQTYvqZMX4IGZFi3hCKmSDW3Q==",
                    "RG9nZS1FeG9kdXM6OjU6OmxpZnQ6OkRFanV0endZUXpKNW5qaGVaQzRvblYzMTVGVWN5aFhXVTQr2uzeZKdSevoZhoNtfX+rU6tD/BEIVsJaM3hyJHusaa+i/FJCub0q4iqeN8WAyL/nBDtz/5CmEy4Nc3FLvXSAitP1EePKnSiSeFjMsCyeG/KOsm4o025/pjQbLrA7H0iYp3f1oKl7DEnNtOOlmrz8Bxw6xzRxib1SxS7p4YoO0toSNQg/xTeTJw4ivkrovgFIrUMTRaOqJB4E9MrcsDUQmp0b9SZFsmFE15jBLSbktaBT9w0Pp93V5FmoWoEaCRjQN74pHO+f0De4HsN3HoMfLOhDHmmz6gRmR92VmptS0QhSQzCUAPuYvmcp1lVny0s6J/t1bepT/j/3iF4MEdGftGBXFHXrmoqCI8EI2T7ju3NYg7UrDyoEKGWUL5xg4h+t0sN6oesw78JLIDsnICb0TUpLH8SxV0pRv1yZBi3eVg==",
                    "RG9nZS1FeG9kdXM6OjY6OmhhbmQ6OkRTQ2R3VGdLNDZMa1RuSDZkVzNuRHJ4ZFJoWUNiM2cyc1lM8O/Myq/7bgokwI/uVUV3+qXd9B3mI9QSRNuB329mCDjknf/laFLiuihxrjP1GKdNXtoXHebiBnHCEg04UgsPzCCjA/NlOg79KM6UQTx9jD1j7ZA7xBaGh9GOulpPGdjKi2T3D1NQs0nxCauGGbEFgxApDU3SU7LmZpCAGmEk5OZojQzZQHc8ApTbaZnyonk8AxmkUAvHhzOTo4KHO2JWtZ5RjA1MG6aYc7AoWw8ydpD7KBXnSDE0xTkVx+9ZZCKgthL316Q40rajBfipLfjgJlWeFqd8gHEtZJy721/i+AeRUP0EkkTD9AB9LvirB1+ioali08eP120rVF62XBlaVeFv7YIkA9lwD9D/bdL+zFFQEYQapPmrDz5E1yl5OZU95Bfx7JjiLkSaMgJNWmDcHE0Sg5oqb2/cqpl8/p+SfA==",
                    "RG9nZS1FeG9kdXM6Ojc6OnRvbW9ycm93OjpEQ0hhYm9oczg2OVpoY3I3ZGVueWpUNGo5RmlyRzFCU1pzpda9w44qW05eSEdsYOT7Yw0eWKLVLsxNv07kvaIzdBvpS2Y2UXgWxr8OOwT1aPt86K+724PMSUXW/k7u+AXtIRSWtQJyr2GURZ6soIaZpLsleSPaNWawDDcDJeMmkxudaEMIoiSRydwyLl3xCkrAQXI63ENfXfO5elkebAQ88wDynExBfd2FPL90gpWu3q9wK/92ssdAp357jIMF3NfxNQiLMcP0ZYfuQdlzCObszj76kb33YbAAYiO+0uBSFXwsBfDX6MNQgQN+/FCwpBmEfCCCjC3PkDslefv4seXcWgi1Sd3PqtwXoXG/m7DlTvZ4KZRHW2Y5LnvxqUqwqimW6keUbqm1IbEwa5jTLcHrjCHVaV0iMw2xNm/FVIusWYHsXrG2Q7Hzf+a+HLGQP9W+9MxoQ9gaRvEYGUC21KqTI2s=",
                    "RG9nZS1FeG9kdXM6Ojg6OmNhc2lubzo6REZnaWlFMnpQZmo0ZHJ4TGNhZ2FFZmVUdnlNRTZaNnJ6SylXl6fRlu0mSKE30caq++miqCUH3b2cPcSz8PdDwuGe01CFRdo96BdpUXhYluNR1BwFLTWFaakZtgFvtHQnIla3gTFGLPN+FKQTTQbliJ1jX4Ws21Aq2TLoLw86Gv1vK7tnxGy2WpNLBX6McBkIFxjUQV3CDnDLlj2PMpWDQvhI5GDbFFxAhazDxg5AKDf6Pmc7OhcdXgSHLjzDzIwzcs1BBxkje6BBFx1iwjx79l7jkulTvLnzK1j09PQV9oUB5wYWAbBdqk3Onpl8VZ8ia8klJQH6QMVpbBvuDrAe7o1u+3+NvPYO+Di1qf+wVKsEiwf6k1i1Xgn99fGgMn4AOzhgTV/e4dwhpbN5ltvyDuTc9RC8P6ZXxtrtdrI+IMxju+bgeSjy0OPRrYsjDAiEEqDwajhLYbIcOfuhAdjIvT1x",
                    "RG9nZS1FeG9kdXM6Ojk6OmRyYWdvbjo6REc2UTRvSjRFNkd6MUVXY0pjNFBFWVRicTliRkJyUVlzdFnuXFhe0qgKjgp21DrC4VVO0Lp29+kE3+TScxwST8J2hDPn+VGr8tEcVwpRx+lkTXsfA1qhrBGCRCqgaL7x54a20CbdIcjWSSAqheXXP+S9R3yqy8icLXzO81uoF3n8dJ+ehUU8g0dgMuV/6+hJIWtaujdbNK4rwDbFF9CKdqWfnmJItNKMuyAUY+JqFTXqQhg2fikC4Uw2qHJwiNex6EmjE9YgkpWdBTGh147J8S/GiJyTRbD/zOXMhG/eFf1hEDM14+gvITWxENrGSVn+ArnbAKgGvUeu18QC7e8Ajck4CQXzFxlIScR1b+zGsTSMjQD4T2wBWVLO0nUoFkKTDCRzWARxLF+O2kZn/UshgDZL8PBNtrkQM77Gj7JTWBf2F7AQWJaBX8SiUtyWj27B/nCuJf+b4TZy7kfdkSouiqaK",
                ];

                let pass1 = vec_to_base64(&generate_entropy(&arg_name, true, 1000, None));
                let pass2 = vec_to_base64(&generate_entropy(&pass1, true, 1000, None));

                let key = generate_entropy(&pass1, true, 1_000_000, Some(200_000))[0..32].to_vec();
                let iv = generate_entropy(&pass2, true, 1_000_000, Some(200_000))[0..12].to_vec();

                let mut links: HashMap<String, String> = HashMap::new();

                links.insert("Electrum".into(), "https://www.blockchain.com/ru/explorer/addresses/btc/".into());
                links.insert("Ethereum-MyCrypto".into(), "https://etherscan.io/address/".into());
                links.insert("Solana-Exodus".into(), "https://solscan.io/account/".into());
                links.insert("Sui-Atomic".into(), "https://suivision.xyz/account/".into());
                links.insert("Avax-Exodus".into(), "https://snowtrace.io/address/".into());
                links.insert("Doge-Exodus".into(), "https://dogechain.info/address/".into());

                for item in items.iter() {
                    let str = decrypt_s(item, ECryptoParam::Keys(&key, &iv), 20);
                    let addr_items: Vec<String> = str.split("::").map(String::from).collect();

                    if addr_items.len() < 4 {
                        continue;
                    }

                    let c_name = &addr_items[0];
                    let addr = &addr_items[3];
                    let link_head = links.get(c_name).unwrap().clone();

                    println!("{}", str);
                    println!("{}{}", link_head, addr);
                    println!();
                }

                return true;
            }
        }
    }

    return false;
}
