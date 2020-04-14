use std::convert::TryInto;
use std::collections::{HashSet, HashMap, VecDeque};
use std::fs;
use std::error::Error;

use rand::prelude::*;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::NoPadding;
use aes::Aes128;

const FIXED_KEY: &[u8] = b"YELLOW SUBMARINE";

type AES128ECB = Ecb<Aes128, NoPadding>;

pub fn pkcs7_pad_block(data: &[u8], block_size: u32) -> Vec<u8> {
    let mut padded = data.to_vec();
    let n_to_pad = block_size - ((data.len() as u32) % block_size);
    if n_to_pad != block_size {
        padded.append(&mut vec![n_to_pad.try_into().unwrap(); n_to_pad.try_into().unwrap()]);
    }
    padded
}

pub fn pkcs7_pad_strip(data: &[u8]) -> Result<Vec<u8>, String> {
    let nbs = data.len();
    let padb = data[nbs-1];
    // println!("nbs = {}, padb = {}", nbs, padb);
    if padb as usize > nbs {
        return Err(String::from("overflow!"))
    }
    if !data.iter().skip(nbs-padb as usize).all(|&b| b == padb) {
        return Err(String::from("invalid pkcs7"))
    }
    Ok(data.iter().take(nbs-padb as usize).cloned().collect::<Vec<u8>>())
}

pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.iter().zip(y.iter())
        .map(|(b1,b2)| b1 ^ b2)
        .collect::<Vec<u8>>()
}

pub fn ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.chunks_exact(16)
        .fold(vec![], |mut prev,curr| {
            let cipher = AES128ECB::new_var(key, Default::default()).unwrap();
            prev.append(&mut cipher.encrypt_vec(curr));
            prev
        })
}

pub fn ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.chunks_exact(16)
        .fold(vec![], |mut prev,curr| {
            let cipher = AES128ECB::new_var(key, Default::default()).unwrap();
            prev.append(&mut cipher.decrypt_vec(curr).unwrap());
            prev
        })
}

pub fn cbc_encrypt(data: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    data.chunks_exact(16)  // TODO: use BlockCipher trait to get BlockSize method vs. having magic number around
        .fold(iv.to_vec(), |prev,curr| {
            let cipher = AES128ECB::new_var(key, iv).unwrap();
            let curr_cipher_block = cipher.encrypt_vec(&xor(curr,&prev));
            res.extend_from_slice(&curr_cipher_block);
            curr_cipher_block
        });
    res
}

pub fn cbc_decrypt(data: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    data.chunks_exact(16)
        .fold(iv.to_vec(), |prev,curr| {
            let cipher = AES128ECB::new_var(key, iv).unwrap();  // TODO: inject a block cipher for generic cbc
            let curr_cipher_block = cipher.decrypt_vec(curr).unwrap();
            res.append(&mut xor(&curr_cipher_block, &prev));
            curr.to_vec()
        });
    res
}

pub fn generate_rand(n: usize) -> Vec<u8> {
    RandStream::new().take(n).collect()
}

struct RandStream {
    generator: ThreadRng,
}

impl RandStream {
    fn new() -> Self {
        RandStream {
            generator: thread_rng()
        }
    }
}

// TODO: Make this generic for all types that implement Rand
impl Iterator for RandStream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.generator.gen())
    }
}

fn random_ecb_or_cbc_encode(data: &[u8]) -> Vec<u8> {
    let mut rng_gen = thread_rng();
    let aes_key = generate_rand(16);
    let iv = generate_rand(16);
    let mut rand_append = generate_rand(rng_gen.gen_range(5,11));
    let mut plaintext = generate_rand(rng_gen.gen_range(5,11));

    plaintext.append(&mut data.to_vec());
    plaintext.append(&mut rand_append);
    let plaintext = pkcs7_pad_block(&plaintext, 16);

    if rand::random() {
        println!("cbc");
        return cbc_encrypt(&plaintext, &iv, &aes_key);
    } else {
        println!("ebc");
        return ecb_encrypt(&plaintext, &aes_key);
    }
}

fn detect_ecb(ciphertext: &[u8]) -> bool {
    let mut uniqs = HashSet::new();
    !ciphertext.chunks(16).all(move |x| uniqs.insert(x))
}

fn ecb_append_oracle(data: &[u8]) -> Vec<u8> {
    let mut footer = base64::decode(&fs::read_to_string("12.txt").unwrap()).unwrap();
    let mut plaintext = data.to_vec();
    plaintext.append(&mut footer);
    ecb_encrypt(&pkcs7_pad_block(&plaintext, 16), &FIXED_KEY)
}

fn crack_ecb_oracle_block(block_number: usize, iv: &[u8]) -> Vec<u8> {
    let mut base = VecDeque::from(iv.to_vec());
    let mut cracked_block = vec![];
    for _i in 0..iv.len() {
        base.pop_front();
        let crafted_input = base.iter()
            .cloned()
            .chain(cracked_block.iter().cloned())
            .collect::<Vec<u8>>();
        let cipher_block = ecb_append_oracle(&base.iter()
            .cloned()
            .collect::<Vec<u8>>())
            .chunks_exact(16)
            .nth(block_number)
            .unwrap().to_vec();
        let cracked_byte = (0..=255)
            .map(|b| {
                let mut input = crafted_input.clone();
                input.push(b);
                (ecb_append_oracle(&input).chunks_exact(16).nth(0).unwrap().to_vec(), input)
            })
            .find(|(output,_)| output == &cipher_block).unwrap().1
            .pop().unwrap();

        cracked_block.push(cracked_byte);
        println!("{:?}", cracked_block);
    }
    cracked_block
}

fn encodeQueryParams(query: &str) -> HashMap<&str,&str> {
    query.split("&")
        .map(|kv| kv.split("=").collect::<Vec<&str>>())
        .filter(|vs| vs.len() == 2)
        .map(|vs| (vs[0], vs[1]))
        .collect::<HashMap<&str,&str>>()
}

struct User {
    email: String,
    uid: u32,
    role: String,
}

impl User {
    fn new(email: &str) -> Self {
        let sanitised_email = email.chars()
            .filter(|&c| "=&{}".find(|b| b == c).is_none())
            .collect::<String>();
        User { 
            email: sanitised_email, 
            uid: random(),
            role: String::from("user"), 
        }
    }

    fn from_map(query_map: &HashMap<&str,&str>) -> Self {
        User {
            email: query_map.get("email").unwrap_or(&"na").to_string(),
            uid:   u32::from_str_radix(&query_map.get("uid").unwrap_or(&"1"), 10).unwrap(),
            role:  query_map.get("role").unwrap_or(&"na").to_string(),
        }
    }

    fn decode(cipherbs: Vec<u8>) -> Self {
        User::from_map(&encodeQueryParams(&String::from_utf8(ecb_decrypt(&cipherbs, FIXED_KEY)).unwrap()))
    }

    fn encode(&self) -> Vec<u8> {
        let query_form = self.serialise();
        ecb_encrypt(&pkcs7_pad_block(query_form.as_bytes(), 16), FIXED_KEY)
    }

    fn serialise(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }
}

fn query_encode(user_data: &str) -> Vec<u8> {
    let mut query = b"comment1=cooking%20MCs;userdata=".to_vec();
    query.extend_from_slice(user_data.as_bytes());
    query.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
    let padded_query = pkcs7_pad_block(query.as_slice(), 16);
    cbc_encrypt(padded_query.as_slice(), &vec![0;16], FIXED_KEY)
}

fn query_decode(ciphertext: &[u8]) -> Vec<u8> {
    cbc_decrypt(ciphertext, &vec![0;16], FIXED_KEY)
}

fn padding_oracle(ciphertext: &[u8]) -> bool {
    pkcs7_pad_strip(&cbc_decrypt(ciphertext, &vec![0;16], FIXED_KEY)).is_ok()
}

fn padding_oracle_crack_adj_blocks(c1: &[u8], c2: &[u8]) -> Vec<u8> {
    let mut p2 = vec![];
    let mut c1v = c1.to_vec();
    c1v.extend_from_slice(c2);
    let block_size: u8 = c1.len().try_into().unwrap();
    for i in 0..block_size {
        for b in 1..255 {
            c1v[(block_size-i) as usize - 1] = b;
            if padding_oracle(&c1v) {
                /* ENTER THE HARD ZONE */
                println!("flex zone: {}", b);
                let i2b = b ^ (i+1);
                // PlaintextByte = Intermediate Byte ^ Original Ciphertext byte from C1
                p2.push(i2b ^ c1[(block_size-i) as usize - 1]);
                // \x(ncracked+1) ^ I2[ncracked] = what to put in for C1   ^^ rearrange top
                c1v[(block_size-i) as usize - 1] = i2b ^ (i+2);
                assert!(i2b ^ c1v[(block_size-i) as usize - 1] == (i+2));
                /* EXIT HARD ZONE */
            }
        }
    }
    p2.reverse();
    p2
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::panic::catch_unwind;
    
    use base64;

    #[test]
    fn challenge9_pkcs7_pad() {
        let block = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        assert_eq!(pkcs7_pad_block(block, 20), expected);
        assert_eq!(pkcs7_pad_block(block, 16), block);
    }
        
    #[test]
    fn challenge10_cbc_inverse() {
        let data = b"YELLOW SUBMARINE";
        let iv = [0 as u8; 16];
        let key = b"YELLOW SUBMARINE";
        let encrypted = pkcs7_pad_block(&cbc_encrypt(data, &iv, key), 16);
        assert_eq!(cbc_decrypt(&encrypted, &iv, key), data.to_vec());
    }

    #[test]
    fn challenge11_aes_generation() {
        let data = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";
        let ciphertext = random_ecb_or_cbc_encode(data);
        if detect_ecb(&ciphertext) {
            println!("EBC");
        } else {
            println!("CBC");
        }
    }
    
    // commenting the test out because it takes a bit of time...
    #[test]
    fn challenge12_ebc_byte_at_a_time() {
        // I'm a little fatigued to refactor the code to return a Result type,
        // so I'll keep the unwraps there knowing that the last block + 1 will likely
        // panic on a UHOH unwrap. And mutable types can't be referenced under an
        // unwind behaviour... so we just print per iteration.
        let _ = catch_unwind(|| {
            let mut res = String::new();
            let mut prev_iv_block = vec![0;16];
            for nblock in 0..{
                prev_iv_block = crack_ecb_oracle_block(nblock, &prev_iv_block);
                res.push_str(&String::from_utf8(prev_iv_block.clone()).unwrap());
                println!("{}", res);
            }
        });
    }

    #[test]
    fn challenge13_query_encode() {
        let query = "a=1&b=2&c=3";
        let mut expected = HashMap::new();
        expected.insert("a", "1");
        expected.insert("b", "2");
        expected.insert("c", "3");
        assert_eq!(encodeQueryParams(query), expected)
    }

    #[test]
    fn challenge13_create_user() {
        let email = "skaterboy&girl@yeet.com&role=admin";
        let expected_email = "skaterboygirl@yeet.comroleadmin";
        assert_eq!(User::new(email).email, expected_email)
    }
    
    #[test]
    fn challenge13_serialise_user() {
        let user = User {
            email: "abc".to_string(),
            uid:  1,
            role: "heyo".to_string(),
        };
        assert_eq!(user.serialise(), "email=abc&uid=1&role=heyo")
    }

    #[test]
    fn challenge13_assume_admin_role() {
        let spoofed_user = User::new("admin");
        let cipherbs = spoofed_user.encode();
        let pad_byte = cipherbs.last().unwrap();

        // remove the padding
        let mut unpadded_cipherbs = spoofed_user.encode().iter().rev()
            .skip_while(|&b| b == pad_byte)
            .cloned()
            .collect::<Vec<u8>>();

        unpadded_cipherbs.reverse();

        // change the last four bytes to be the bytes corresponding to admin

        // This would be easy if I hard-coded the uid like the challenge told me to do
        // as then I can craft a block that starts with admin, and then just add it onto the end
        // but nOPE i decided to be a GOOD ENGINEER and randomise my ULIDs.
        // Todo: be a bad engineer and make predictable uids
    }

    #[test]
    fn challenge15_pkcs7_pad_validation() {
        let input = b"ICE ICE BABY\x04\x04\x04\x04";
        let res = b"ICE ICE BABY";
        assert_eq!(pkcs7_pad_strip(input).unwrap(), res);

        let input = b"ICE ICE BABY\x01\x02\x03\x04";
        assert_eq!(pkcs7_pad_strip(input).is_err(), true);

        let input = b"ICE ICE BABY\x05\x05\x05\x05";
        assert_eq!(pkcs7_pad_strip(input).is_err(), true);
    }

    #[test]
    fn challenge16_cbc_bitflip_attack() {
        // Some working out...                 block pad               
        // "comment1=cooking%20MCs;userdata=AAAAAAAAAAAAAAAA>admin8true>;comment2=%20like%20a%20pound%20of%20bacon"
        //                                                  ^     ^    ^
        //                              some character such that when we bit flip in first block, it becomes '=' or ';'
        // ; : 00111011 = \x3B
        // = : 00111101 = \x3D          
        // flip character for ; has bits 00111110  3E -> >
        // flip character for = has bits 00111000  38 -> 8
        // then we flip both with mask   00000101
        //                               --------
        //                               00111101 '='
        //                               00111011

        let mut ciphertext = query_encode("AAAAAAAAAAAAAAAA>admin8true");
        ciphertext[2*16 + 0] = ciphertext[2*16 + 0] ^ 5;  
        ciphertext[2*16 + 6] = ciphertext[2*16 + 6] ^ 5;  
        println!("{}", String::from_utf8(query_decode(&ciphertext)).unwrap());
    }

    #[test]
    fn challenge17_cbc_padding_oracle_attack() {
        let plaintext_b64 = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=";
        let padded_plaintext_bs = pkcs7_pad_block(&base64::decode(plaintext_b64).unwrap(), 16);
        let ciphertext = cbc_encrypt(&padded_plaintext_bs, &vec![0;16], FIXED_KEY);
        let mut res = vec![];
        ciphertext.chunks_exact(16).rev()
            .zip(ciphertext.chunks_exact(16).rev().next())
            .for_each(|(c2,c1)| res.append(&mut padding_oracle_crack_adj_blocks(c1, c2)));
        println!("The secret is: {}", String::from_utf8(res).unwrap());
    }
}
