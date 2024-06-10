use bip39::{Mnemonic, Language, Seed};

pub struct BIP39Mnemonic;

impl BIP39Mnemonic {
    pub fn to_mnemonic(seed: &[u8]) -> String {
        Mnemonic::from_entropy(seed, Language::English).unwrap().phrase().to_string()
    }

    pub fn from_mnemonic(mnemonic: &str) -> Vec<u8> {
        Mnemonic::from_phrase(mnemonic, Language::English).unwrap().entropy().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_mnemonic() {
        let seed = [0x00; 16];
        let mnemonic = BIP39Mnemonic::to_mnemonic(&seed);
        assert_eq!(mnemonic.split_whitespace().count(), 12);
    }

    #[test]
    fn test_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = BIP39Mnemonic::from_mnemonic(mnemonic);
        assert_eq!(seed.len(), 16);
    }
}
