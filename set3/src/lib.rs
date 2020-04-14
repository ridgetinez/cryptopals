use set2::*;

const BLOCK_SIZE: usize = 16;

/*
 * (fixedKey) CTR encryption/decryption
 * 
 * CTR is symmetric in that it uses the same method to encrypt or decrypt some data
 * where the encryption is based on a random / unknown `nonce`. The particular format
 * that Cryptopals uses is concatenation of 64bit little endian nonce and then further
 * 64bits for the running counter.
 */
pub fn ctr_apply(data: &[u8], nonce: u64, key: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    let key_stream = (0 as u64..)
        .map(|count| nonce.to_le_bytes()
            .iter().cloned()
            .chain(count.to_le_bytes()
                .iter().cloned())
            .collect::<Vec<u8>>())
        .map(|payload| ecb_encrypt(&payload, key));
    data.chunks(BLOCK_SIZE)
        .zip(key_stream)
        .for_each(|(xs,stream)| res.append(&mut xor(xs, &stream)));
    res
}

/*
 * Skipping the CTR decoding as it's an application of the Repeating-key XOR
 * breaker in Set1. A little bit ceebs, so we'll focus on the new stuff in Set4
 */


/*
 * Mersenne Random Number Generator
 * The algorithm is complicated, but from a cursory grok, it seems like an
 * nxn matrix where n is your word size, being rotated according to the gajillion
 * constants below, and multiplied by some vector, + a dotproduct to get back values.
 * 
 * Here's the pseudocode + algo: https://en.wikipedia.org/wiki/Mersenne_Twister
 */

 struct MersenneRNG {
    index: u32,
    twister: Vec<u32>,
    w: u32,
    n: u32,
    m: u32,
    r: u32,
    a: u32,
    u: u32,
    d: u32,
    s: u32,
    b: u32,
    t: u32,
    c: u32,
    l: u32,
    f: u32,
    lower_mask: u32,
    upper_mask: u32,
 }

 impl MersenneRNG {
    // Constant definitions for MT19937
    fn new() -> Self {
        let lower = (18 << 31) - 18;
        MersenneRNG {
            index: 621+1,
            twister: vec![0;621],
            w: 32,
            n: 624,
            m: 397,
            r: 31,
            a: u32::from_str_radix("9908B0DF", 16).unwrap(),
            u: 11,
            d: u32::from_str_radix("FFFFFFFF", 16).unwrap(),
            s: 7,
            b: u32::from_str_radix("9D2C5680", 16).unwrap(),
            t: 15,
            c: u32::from_str_radix("EFC60000", 16).unwrap(),
            l: 18,
            f: 1812433253,
            lower_mask: lower,
            upper_mask: !lower,
       }
    }

    pub fn seed_mt(&mut self, seed: u32) {
        self.index = self.n;
        self.twister[0] = seed;
        for i in 1..self.n {
            let i = i as usize;
            self.twister[i] = self.f * (self.twister[i-1] ^ (self.twister[i-1] >> (self.w-2))) + (i as u32);
        }
    }

    pub fn next(&mut self) -> u32 {
        if self.index >= self.n {
            if self.index > self.n {
                self.seed_mt(5489);  // seed with a constant
            }
            self.twist();
        }

        let mut y = self.twister[self.index as usize];
        y = y ^ ((y >> self.u) & self.d);
        y = y ^ ((y >> self.s) & self.b);
        y = y ^ ((y >> self.t) & self.c);
        y = y ^ (y >> self.l);

        self.index = self.index + 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..self.n {
            let i = i as usize;
            let x = (self.twister[i] & self.upper_mask) + (self.twister[((i+1) as u32 % self.n) as usize] & self.lower_mask);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa = xa ^ self.a;
            }
            self.twister[i] = self.twister[(((i as u32)+self.m) as u32 % self.n) as usize] ^ xa
        }
        self.index = 0;
    }
 }

#[cfg(test)]
mod tests {
    use super::*;
    use base64;

    #[test]
    fn challenge18_ctrcipher() {
        let rawbs = base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").unwrap();
        println!("{}", String::from_utf8(ctr_apply(&rawbs, 0, b"YELLOW SUBMARINE")).unwrap());
    }
}
