use rust_matasano::*;
use std::fs;
use std::io::{BufReader, BufRead};
use std::cmp::Ordering;
use openssl::symm;

#[test]
fn challenge1_hex2base64() {
    assert_eq!(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
}

#[test]
fn challenge2_fixedxor() {
    assert_eq!(fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").unwrap(), "746865206b696420646f6e277420706c6179")
}

#[test]
fn challenge3_singlexorcipher() {
    let english_freq_map = calculate_frequency(&fs::read_to_string("muchadoaboutnothing.txt").unwrap());
    let cipher = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
    let (_, plaintext_bs, _) = decode_single_xor(cipher.as_slice(), &english_freq_map);
    let plaintext = String::from_utf8(plaintext_bs).unwrap();
    println!("The code is: {}", plaintext)
}

#[test]
fn challenge4_detectsinglexorcipher() {
    let reader = BufReader::new(fs::File::open("4.txt").unwrap());
    let english_freq_map = calculate_frequency(&fs::read_to_string("muchadoaboutnothing.txt").unwrap());
    reader.lines()
        .map(|line| hex::decode(line.unwrap()).unwrap())
        .map(|cipher| decode_single_xor(cipher.as_slice(), &english_freq_map))
        .max_by(|&(_,_,v1),&(_,_,v2)| v1.partial_cmp(&v2).unwrap_or(Ordering::Equal)).iter()
        .for_each(|(_,bs,_)| println!("The code is: {}", String::from_utf8(bs.to_vec()).unwrap()))
}

#[test]
fn challenge5_encode_repeatingkey_xor() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    assert_eq!(hex::encode(apply_repeatingkey_xor(plaintext.as_bytes(), key.as_bytes())), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
}

#[test]
fn challenge6_hammingdistance() {
    assert_eq!(hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()), 37);
}

#[test]
fn challenge6_tranpose() {
    let matrix = vec![1,2,3,4,5,6];
    let transposed = transpose(matrix.as_slice(), 3);
    assert_eq!(transposed, vec![vec![1,4], vec![2,5], vec![3,6]]);
}

#[test]
fn challenge6_decode_repeatingkey_xor() {
    let cipher = base64::decode(&fs::read_to_string("6.txt").unwrap()).unwrap();
    let freq_map = calculate_frequency(&fs::read_to_string("muchadoaboutnothing.txt").unwrap());
    let key = find_repeatingkey_xor_key(&cipher, &freq_map);
    let plaintext = String::from_utf8(apply_repeatingkey_xor(&cipher, &key)).unwrap();
    println!("The key is: {}", String::from_utf8(key).unwrap());
    println!("{}", plaintext);
}

#[test]
fn challenge7_decode_aes_128_ecb() {
    let key = b"YELLOW SUBMARINE";
    let data = base64::decode(&fs::read_to_string("7.txt").unwrap()).unwrap();
    let message = symm::decrypt(symm::Cipher::aes_128_ecb(), key, None, &data).unwrap();
    println!("The message is: {}", String::from_utf8(message).unwrap());
}

#[test]
fn challenge8_detect_aes_128_ecb() {
    let reader = BufReader::new(fs::File::open("4.txt").unwrap());
    /*
    reader.lines()
        .map(|line| hex::decode(line.unwrap()).unwrap())
        .for_each(|bs| println!("waddup"));
        */
}

/* Hey this code is actually useful for some of the weekly activities! In week 4 we need to deduce which of
   the two cipher texts is encoded via a vigenere like cipher. Let's take it a step forward and try to decrypt it! */

#[test]
fn coincidence_italian_feature() {
    /*
    let cipher = fs::read_to_string("coincidence2.txt").unwrap();
    let freq_map = calculate_frequency(&fs::read_to_string("divinacommedia.txt").unwrap());
    let key = find_repeatingkey_xor_key(cipher.as_bytes(), &freq_map);
    let plaintext = String::from_utf8(apply_repeatingkey_xor(cipher.as_bytes(), &key)).unwrap();
    println!("The key is: {}", String::from_utf8(key).unwrap());
    println!("{}", plaintext);
    */

    let cipher = fs::read_to_string("coincidence2.txt").unwrap();
    let freq_map = calculate_frequency(&fs::read_to_string("muchadoaboutnothing.txt").unwrap());
    let msg = decode_single_xor(cipher.as_bytes(), &freq_map).1;
    println!("The code is: {}", String::from_utf8(msg).unwrap());
}
