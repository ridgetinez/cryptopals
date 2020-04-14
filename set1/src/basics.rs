use hex;
use base64;

pub fn hex_to_base64(code: &str) -> String {
    hex::decode(code).map(|bs| base64::encode(bs)).unwrap()
}