use bip38::{Decrypt, Encrypt, EncryptWif, Error};

pub struct BIP38Encryption;

impl BIP38Encryption 
{
    pub fn encrypt_key(key: &[u8; 32], passphrase: &str, compress: bool) -> Result<String, Error> 
    {
        key.encrypt(passphrase, compress)
    }

    pub fn decrypt_key(encrypted_key: &str, passphrase: &str) -> Result<([u8; 32], bool), Error> 
    {
        encrypted_key.decrypt(passphrase)
    }

    pub fn encrypt_wif(wif: &str, passphrase: &str) -> Result<String, Error> 
    {
        wif.encrypt_wif(passphrase)
    }

    pub fn decrypt_wif(encrypted_wif: &str, passphrase: &str) -> Result<String, Error> 
    {
        encrypted_wif.decrypt_to_wif(passphrase)
    }
}

#[cfg(test)]
mod tests 
{
    use super::*;

    #[test]
    fn test_encrypt_key() 
    {
        let key = [0x11; 32];
        let passphrase = "strong_pass";
        let encrypted_key = BIP38Encryption::encrypt_key(&key, passphrase, true).unwrap();
        assert!(!encrypted_key.is_empty());
    }

    #[test]
    fn test_decrypt_key() 
    {
        let key = [0x11; 32];
        let passphrase = "strong_pass";
        let encrypted_key = BIP38Encryption::encrypt_key(&key, passphrase, true).unwrap();
        let (decrypted_key, compress) = BIP38Encryption::decrypt_key(&encrypted_key, passphrase).unwrap();
        assert_eq!(key, decrypted_key);
        assert!(compress);
    }

    #[test]
    fn test_encrypt_wif() 
    {
        let wif = "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp";
        let passphrase = "strong_pass";
        let encrypted_wif = BIP38Encryption::encrypt_wif(wif, passphrase).unwrap();
        assert!(!encrypted_wif.is_empty());
    }

    #[test]
    fn test_decrypt_wif() 
    {
        let wif = "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp";
        let passphrase = "strong_pass";
        let encrypted_wif = BIP38Encryption::encrypt_wif(wif, passphrase).unwrap();
        let decrypted_wif = BIP38Encryption::decrypt_wif(&encrypted_wif, passphrase).unwrap();
        assert_eq!(wif, decrypted_wif);
    }
}