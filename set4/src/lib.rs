extern crate curl;

use crypto::sha1::Sha1;
use crypto::digest::Digest;
use curl::easy::Easy;
use std::error::Error;
use std::time::{Instant,Duration};

fn secret_prefix_mac(message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.input(&b"YELLOW SUBMARINE".iter().cloned().chain(message.iter().cloned()).collect::<Vec<u8>>());
    hasher.result_str().as_bytes().iter().cloned().collect::<Vec<u8>>()
}

fn check_mac(message: &[u8], recv_mac: &[u8]) -> bool {
    let message_mac = secret_prefix_mac(message);
    recv_mac.iter().zip(message_mac.iter()).all(|(b1,b2)| b1 == b2)
}

/* TODO: Vendor an implementation of SHA1 for challenges #29, #30 as it requires looking at internal state of SHA1 */

fn send_attack_request(endpoint: &str) -> u32 {
    let mut easy = Easy::new();
    easy.url(&endpoint)
        .map_or(0, |_x| easy.perform()
            .map_or(0, |_x| easy.response_code().map_or(0, |code| code)))
}

fn create_attack_endpoint(base: &str, suffix: &str) -> String {
    format!("{}/crack?filepath={}&signature={}", base, "fixed", suffix)
}

fn time_leak_attack(endpoint: &str) -> String {
    let mut res = String::new();
    let hexchars = "0123456789abcdef";
    while true {
        let mut best_char = '0';
        let mut max_elapsed = Duration::new(0,0);
        for c in hexchars.chars() {
            // let c: u8 = c;
            res.push(c);
            let prev = Instant::now();
            let status_code = send_attack_request(&create_attack_endpoint(endpoint, &res));
            let curr_elapsed = Instant::now().duration_since(prev);
            if status_code == 0 {
                res.pop();
                continue;
            }
            if status_code == 202 {
                return res;
            }
            if curr_elapsed > max_elapsed {
                max_elapsed = curr_elapsed;
                best_char = c;
            }
            res.pop();
        }
        res.push(best_char);
        println!("{}", res);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge27_secret_prefix_mac() {
        let mut message = b"SHINY SWORD MY DIAMOND".iter().cloned().collect::<Vec<u8>>();
        let mac = secret_prefix_mac(&message);
        assert!(check_mac(&message, &mac));
        message[0] = 133;
        assert!(!check_mac(&message, &mac))
    }

    #[test]
    fn challenge28_length_extension_sha1_mac() {
        println!("Deferred until I can find a nice vendor... might be a case for Python here since I can look into any object :P")
    }

    #[test]
    fn challenge30_artificial_time_leak() {
        println!("{}", time_leak_attack("http://localhost:8000"));
    }
}
