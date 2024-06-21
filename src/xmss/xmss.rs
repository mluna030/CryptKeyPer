use crate::hash_function::Sha256HashFunction;
use crate::random_key_generator::OsRandomKeyGenerator;
use crate::drbg::HmacDrbg;
use crate::xmss::merkle::MerkleTree;
use crate::xmss::wots::Wots;

pub struct Xmss {
    pub index: usize,
    pub remaining: usize,
    pub private_seed: Vec<u8>,
    pub public_seed: Vec<u8>,
    pub wots_keys: Vec<Wots>,
    pub merkle_tree: MerkleTree,
}

impl Xmss {
    pub fn new(signatures: usize, seed: Option<&[u8]>) -> Self {
        let seed = match seed {
            Some(s) => s.to_vec(),
            None => OsRandomKeyGenerator::generate_key(48),
        };

        let private_seed = HmacDrbg::new(&seed, None).generate(48);
        let public_seed = HmacDrbg::new(&seed, Some(&seed)).generate(48);

        let mut wots_keys = Vec::new();
        for _ in 0..signatures {
            wots_keys.push(Wots::new(&private_seed, 16));
        }

        let leaves: Vec<String> = wots_keys
            .iter()
            .map(|wots| wots.public_key.join(""))
            .collect();

        let merkle_tree = MerkleTree::new(leaves);

        Xmss {
            index: 0,
            remaining: signatures,
            private_seed,
            public_seed,
            wots_keys,
            merkle_tree,
        }
    }

    pub fn sign(&mut self, message: &[u8]) -> (usize, Vec<String>, Vec<String>) {
        let wots = &self.wots_keys[self.index];
        let signature = wots.sign(message);
        let auth_path = self.merkle_tree.get_auth_path(self.index);
        self.index += 1;
        self.remaining -= 1;
        (self.index - 1, signature, auth_path)
    }

    pub fn verify(
        &self,
        message: &[u8],
        index: usize,
        signature: &[String],
        auth_path: &[String],
    ) -> bool {
        let wots = &self.wots_keys[index];
        let is_valid = wots.verify(message, signature);

        if !is_valid {
            return false;
        }

        let mut hash = Sha256HashFunction::hash_hex(signature.join("").as_bytes());
        let mut idx = index;

        for sibling in auth_path {
            let combined = if idx % 2 == 0 {
                format!("{}{}", hash, sibling)
            } else {
                format!("{}{}", sibling, hash)
            };
            hash = Sha256HashFunction::hash_hex(combined.as_bytes());
            idx /= 2;
        }

        hash == self.merkle_tree.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmss_sign_verify() {
        let mut xmss = Xmss::new(16, None);
        let message = b"hello world";
        let (index, signature, auth_path) = xmss.sign(message);
        assert!(xmss.verify(message, index, &signature, &auth_path));
    }
}