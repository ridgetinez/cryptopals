use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::fs;

use base64;
use hex;

pub fn hex_to_base64(code: &str) -> String {
    hex::decode(code)
        .map(|bs| base64::encode(&String::from_utf8(bs).unwrap()))
        .unwrap()
}

pub fn fixed_xor(a: &str, b: &str) -> Result<String, Box<dyn Error>> {
    let a = hex::decode(a)?;
    let b = hex::decode(b)?;
    Ok(hex::encode(
        a.iter()
            .zip(b.iter())
            .map(|(b1, b2)| b1 ^ b2)
            .collect::<Vec<u8>>(),
    ))
}

pub fn decode_single_xor(a: &[u8], freq_map: &HashMap<u8,f32>) -> (u8,Vec<u8>,f32) {
    (0..=255)
        .map(|k| {
            // BORROWING: Because xord will be moved at the end of the lambda, must do read ops before the move
            //            so we couldn't have return (k, xord, english_confidence(xord.as_slice(), freq_map))
            //            as xord in english_confidence is empty after being moved. This happens for datatypes
            //            that aren't tagged as Clone.
            let xord = single_xor(a, k);
            let conf = english_confidence(xord.as_slice(), freq_map);
            (k, xord, conf)
        })
        .max_by(|&(_,_,a),&(_,_,b)| a.partial_cmp(&b).unwrap_or(Ordering::Equal))
        .unwrap()
}

pub fn english_confidence(a: &[u8], freq_map: &HashMap<u8,f32>) -> f32 {
    a.iter()
        .map(|c| freq_map.get(c).unwrap_or(&0.0))
        .sum()
}

pub fn single_xor(cipher: &[u8], key: u8) -> Vec<u8> {
    cipher.iter()
        .map(|b| b ^ key)
        .collect::<Vec<u8>>()
}

pub fn calculate_frequency(s: &str) -> HashMap<u8, f32> {
    let mut freq_map = HashMap::new();
    for &b in s.as_bytes() {
        freq_map.insert(b, freq_map.get(&b).map_or_else(|| 1.0, |x| x + 1.0));
    }
    freq_map
        .iter_mut()
        .for_each(|(_, v)| *v = *v / (s.len() as f32));
    freq_map
}

pub fn encode_repeatingkey_xor(plaintext: &str, key: &str) -> String {
    hex::encode(
        plaintext
            .as_bytes()
            .iter()
            .zip(key.as_bytes().iter().cycle())
            .map(|(p, k)| p ^ k)
            .collect::<Vec<u8>>(),
    )
}

// Assumes that x and y are of same [u8] length for valid distance
pub fn hamming_distance(x: &[u8], y: &[u8]) -> u32 {
    x.iter()
        .zip(y.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

// Take 4 average over the four
fn decode_repeatingkey_size(bs: &[u8]) -> u32 {
    let normal_dist = |ksize: u32| hamming_distance(&bs[..(4*ksize as usize)], &bs[(4*ksize as usize)..(4*2*ksize as usize)]) as f64 / (ksize) as f64;
    (2..=40).min_by(|&ksize1, &ksize2| {
        normal_dist(ksize1)
            .partial_cmp(&normal_dist(ksize2))
            .unwrap_or(Ordering::Equal)
    }).unwrap()
}

pub fn transpose(matrix: &[u8], chunksize: usize) -> Vec<Vec<u8>> {
    let mut transposed_chunks = vec![vec![0; matrix.len() / chunksize]; chunksize];
    matrix.chunks_exact(chunksize)
        .enumerate()
        .for_each(|(i, bs)| {
            bs.iter()
                .enumerate()
                .for_each(|(j, &x)| transposed_chunks[j][i] = x)
        });
    transposed_chunks
}

pub fn apply_repeatingkey_xor(cipher: &[u8], key: &[u8]) -> Vec<u8> {
    cipher.iter()
        .zip(key.iter().cycle())
        .map(|(b,k)| b ^ k)
        .collect::<Vec<u8>>()
}

pub fn find_repeatingkey_xor_key(cipher: &[u8], freq_map: &HashMap<u8,f32>) -> Vec<u8> {
    // The cipher is given in base64 encoding
    // let cipher_bs = base64::decode(cipher).unwrap();
    // Find minimum normalised hamming_distance
    let keysize = decode_repeatingkey_size(cipher) as usize;
    let single_xor_chunks = transpose(cipher, keysize); 

    single_xor_chunks.iter()
        .map(|bs| decode_single_xor(bs, &freq_map).0)
        .collect::<Vec<u8>>()
}