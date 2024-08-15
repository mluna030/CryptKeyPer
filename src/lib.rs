pub mod hash_function;
pub mod drbg;
pub mod random_key_generator;
pub mod mnemonic;
pub mod xmss;

pub fn add(left: usize, right: usize) -> usize 
{
    left + right
}
pub fn create_xmss(signatures: usize, mnemonic: Option<&str>) -> Result<xmss::Xmss, String> 
{
    xmss::Xmss::new(signatures, mnemonic)
}

#[cfg(test)]
mod tests 
{
    use super::*;

    #[test]
    fn test_add() 
    {
        let result = add(2, 2);
        assert_eq!(result, 4, "Expected 2 + 2 to equal 4");
    }

    #[test]
    fn test_create_xmss() 
    {
        let passphrase = "strong_pass";
        let xmss_result = create_xmss(16, Some(passphrase));
        assert!(xmss_result.is_ok(), "Expected XMSS creation to succeed, but it failed.");
    }

    #[test]
    fn test_xmss_sign_and_verify() 
    {
        let passphrase = "strong_pass";
        let mut xmss = create_xmss(16, Some(passphrase))
            .expect("Expected XMSS creation to succeed, but it failed.");

        let message = b"hello world";

        let (index, signature, auth_path) = xmss.sign(message)
            .expect("Expected signing to succeed, but it failed.");

        let is_valid = xmss.verify(message, index, &signature, &auth_path)
            .expect("Expected verification process to complete, but it encountered an error.");

        assert!(is_valid, "Expected the signature to be valid, but it was not.");
    }
}