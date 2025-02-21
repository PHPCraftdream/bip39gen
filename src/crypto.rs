#![allow(dead_code)]

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
        }
    }

    return false;
}
