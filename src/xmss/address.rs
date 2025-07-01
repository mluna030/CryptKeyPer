/// XMSS Address structure as defined in RFC 8391
/// Used to prevent multi-target attacks by domain separation
#[derive(Debug, Clone, Copy)]
pub struct XmssAddress {
    pub layer: u32,
    pub tree: u64,
    pub address_type: AddressType,
    pub ots_address: u32,
    pub chain_address: u32,
    pub hash_address: u32,
    pub key_and_mask: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    OtsHashAddress = 0,
    LTreeAddress = 1,
    HashTreeAddress = 2,
}

impl XmssAddress {
    pub fn new() -> Self {
        Self {
            layer: 0,
            tree: 0,
            address_type: AddressType::OtsHashAddress,
            ots_address: 0,
            chain_address: 0,
            hash_address: 0,
            key_and_mask: 0,
        }
    }

    pub fn set_ots_address(&mut self, ots_address: u32) {
        self.address_type = AddressType::OtsHashAddress;
        self.ots_address = ots_address;
    }

    pub fn set_chain_address(&mut self, chain_address: u32) {
        self.chain_address = chain_address;
    }

    pub fn set_hash_address(&mut self, hash_address: u32) {
        self.hash_address = hash_address;
    }

    pub fn set_key_and_mask(&mut self, key_and_mask: u32) {
        self.key_and_mask = key_and_mask;
    }

    pub fn set_tree_address(&mut self, tree_address: u32) {
        self.address_type = AddressType::HashTreeAddress;
        self.ots_address = tree_address;
    }

    pub fn set_tree_height(&mut self, tree_height: u32) {
        self.chain_address = tree_height;
    }

    pub fn set_tree_index(&mut self, tree_index: u32) {
        self.hash_address = tree_index;
    }

    pub fn set_ltree_address(&mut self, ltree_address: u32) {
        self.address_type = AddressType::LTreeAddress;
        self.ots_address = ltree_address;
    }
    
    pub fn set_type(&mut self, address_type: AddressType) {
        self.address_type = address_type;
    }

    /// Convert address to bytes for hashing
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        
        bytes[0..4].copy_from_slice(&self.layer.to_be_bytes());
        bytes[4..12].copy_from_slice(&self.tree.to_be_bytes());
        bytes[12..16].copy_from_slice(&(self.address_type as u32).to_be_bytes());
        bytes[16..20].copy_from_slice(&self.ots_address.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.chain_address.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.hash_address.to_be_bytes());
        bytes[28..32].copy_from_slice(&self.key_and_mask.to_be_bytes());
        
        bytes
    }
}

impl Default for XmssAddress {
    fn default() -> Self {
        Self::new()
    }
}