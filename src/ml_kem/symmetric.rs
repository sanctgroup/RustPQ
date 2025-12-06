use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake128, Shake256,
};

pub fn hash_h(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

pub fn hash_g(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    hasher.finalize().into()
}

pub struct XofState {
    reader: sha3::Shake128Reader,
}

impl XofState {
    pub fn new(seed: &[u8], i: u8, j: u8) -> Self {
        let mut shake = Shake128::default();
        Update::update(&mut shake, seed);
        Update::update(&mut shake, &[i, j]);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

pub struct PrfState {
    reader: sha3::Shake256Reader,
}

impl PrfState {
    pub fn new(key: &[u8; 32], nonce: u8) -> Self {
        let mut shake = Shake256::default();
        Update::update(&mut shake, key);
        Update::update(&mut shake, &[nonce]);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

pub fn kdf(input: &[u8]) -> [u8; 32] {
    let mut shake = Shake256::default();
    Update::update(&mut shake, input);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}
