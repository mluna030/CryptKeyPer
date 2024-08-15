use crate::hash_function::Sha256HashFunction;
use crate::random_key_generator::OsRandomKeyGenerator;
use crate::drbg::HmacDrbg;
use crate::xmss::merkle::MerkleTree;
use crate::xmss::wots::Wots;
use crate::mnemonic::{BIP38Encryption};

pub struct Xmss {
    pub index: usize,
    pub remaining: usize,
    pub private_seed: Vec<u8>,
    pub public_seed: Vec<u8>,
    pub wots_keys: Vec<Wots>,
    pub merkle_tree: MerkleTree,
}

impl Xmss {
    pub fn new(signatures: usize, mnemonic: Option<&str>) -> Result<Self, String> 
    {
        let seed = if let Some(phrase) = mnemonic 
        {
            let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
                .map_err(|e| format!("Invalid mnemonic: {}", e))?;
            Seed::new(&mnemonic, "").as_bytes().to_vec()
        } else {
            OsRandomKeyGenerator::generate_key(48)
        };

        let private_seed = HmacDrbg::new(&seed, None).generate(48);
        let public_seed = HmacDrbg::new(&seed, Some(&seed)).generate(48);

        let mut wots_keys = Vec::new();
        for _ in 0..signatures 
        {
            wots_keys.push(Wots::new(&private_seed, 16));
        }

        let leaves: Vec<String> = wots_keys
            .iter()
            .map(|wots| wots.public_key.join(""))
            .collect();

        let merkle_tree = MerkleTree::new(leaves);

        Ok
        (
            Xmss 
            {
                index: 0,
                remaining: signatures,
                private_seed,
                public_seed,
                wots_keys,
                merkle_tree,
            }
        )
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<(usize, Vec<String>, Vec<String>), String> 
    {
        if self.index >= self.wots_keys.len()
        {
            return Err("No more signatures available".to_string());
        }
        let wots = &self.wots_keys[self.index];
        let signature = wots.sign(message);
        let auth_path = self.merkle_tree.get_auth_path(self.index);
        self.index += 1;
        self.remaining -= 1;
        Ok
        (
            (
                self.index - 1, 
                signature, 
                auth_path
            )
        )
    }

    pub fn verify(&self, message: &[u8], index: usize, signature: &[String], auth_path: &[String]) -> bool 
    {
        if index >= self.wots_keys.len() 
        {
            return Err("Invalid index for verification.".to_string());
        }
        let wots = &self.wots_keys[index];
        let is_valid = wots.verify(message, signature);

        if !is_valid 
        {
            return Ok(false)
        }

        let mut hash = Sha256HashFunction::hash_hex(signature.join("").as_bytes());
        let mut idx = index;

        for sibling in auth_path {
            let combined = if idx % 2 == 0 {
                [hash.as_ref(), sibling.as_ref()].concat()
            } else {
                [sibling.as_ref(), hash.as_ref()].concat()
            };
            hash = Sha256HashFunction::hash(&combined);
            idx /= 2;
        }

        Ok
        (
            hash == self.merkle_tree.root.unwrap()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmss_sign_verify() 
    {
        let mut xmss = Xmss::new(16, None);
        let message = b"hello world";
        let (index, signature, auth_path) = xmss.sign(message);
        assert!(xmss.verify(message, index, &signature, &auth_path));
    }
}