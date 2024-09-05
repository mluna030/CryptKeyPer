pub mod hash_function;
pub mod drbg;
pub mod random_key_generator;
pub mod mnemonic;
pub mod xmss;

pub fn add(left: usize, right: usize) -> usize 
{
    left + right
}
pub fn create_xmss(signatures: usize) -> Result<xmss::xmss::Xmss, String> 
{
    xmss::xmss::Xmss::new(signatures)
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
        let xmss_result = create_xmss(16);
        assert!(xmss_result.is_ok(), "Expected XMSS creation to succeed, but it failed.");
    }
}