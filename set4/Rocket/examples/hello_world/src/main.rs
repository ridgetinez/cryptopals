#![feature(proc_macro_hygiene)]

#[macro_use] extern crate rocket;

#[cfg(test)] mod tests;

use rocket::http::{RawStr,Status};
use std::thread;
const secret_signature: &str = "deadbeef";

#[get("/")]
fn hello() -> String {
    format!("Howdy! Use queries in the URL to crack my secret key!")
}

#[get("/crack?<filepath>&<signature>")]
fn crack_me(filepath: &RawStr, signature: &RawStr) -> Status {
    if (unsafe_cmp(secret_signature.as_bytes(), signature.as_str().as_bytes())) {
        println!("Ok... fine I guess you're not a simp.");
        return Status::Accepted
    } else {
        println!("Hah! What a simp.");
        return Status::NotAcceptable
    }
}

fn unsafe_cmp(a: &[u8], b: &[u8]) -> bool {
    for (i,x) in a.iter().enumerate() {
        if *x != b[i] { return false }
        thread::sleep_ms(50);  // adding artificial time delay...
    }
    return a.len() == b.len();
}

fn main() {
    rocket::ignite().mount("/", routes![hello, crack_me]).launch();
}
