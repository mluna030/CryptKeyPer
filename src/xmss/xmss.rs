use crate::hash_function::hash_function::Sha256HashFunction;
use crate::random_key_generator::random_key_generator::OsRandomKeyGenerator;
use crate::drbg::drbg::HmacDrbg;
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
    pub fn new(signatures: usize) -> Result<Self, String> {
        let seed = OsRandomKeyGenerator::generate_key(48);
        let private_seed = HmacDrbg::new(&seed, None).generate(48);
        let public_seed = HmacDrbg::new(&seed, Some(&seed)).generate(48);
        let mut wots_keys = Vec::new();
        for _ in 0..signatures {
            wots_keys.push(Wots::new(&private_seed, 16));
        }
        let leaves: Vec<[u8; 32]> = wots_keys
            .iter()
            .flat_map(|wots| wots.public_key.clone()) 
            .collect();

        let merkle_tree = MerkleTree::new(leaves);

        Ok(Xmss {
            index: 0,
            remaining: signatures,
            private_seed,
            public_seed,
            wots_keys,
            merkle_tree,
        })
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<(usize, Vec<[u8; 32]>, Vec<[u8; 32]>), String> {
        if self.index >= self.wots_keys.len() {
            return Err("No more signatures available".to_string());
        }
        let wots = &self.wots_keys[self.index];
        let signature = wots.sign(message)?; 
    
        let auth_path = self.merkle_tree.get_auth_path(self.index);
        
        self.index += 1;
        self.remaining -= 1;
        Ok((self.index - 1, signature, auth_path))
    }

    pub fn verify(
        &self,
        message: &[u8],
        index: usize,
        signature: &[Vec<u8>],
        auth_path: &[Vec<u8>],
    ) -> bool {
        if index >= self.wots_keys.len() {
            return false;
        }
    
        let wots = &self.wots_keys[index];
        let is_valid = wots.verify(message, signature).unwrap();
    
        if !is_valid {
            return false;
        }
    
        let mut hash = Sha256HashFunction::hash(&signature.concat());
        let mut idx = index;
    
        for sibling in auth_path {
            let combined: Vec<u8> = if idx % 2 == 0 {
                hash.iter().chain(sibling.iter()).cloned().collect() 
            } else {
                sibling.iter().chain(hash.iter()).cloned().collect() 
            };
            hash = Sha256HashFunction::hash(&combined);
            idx /= 2;
        }
    
        hash == self.merkle_tree.root.unwrap()
    }
}