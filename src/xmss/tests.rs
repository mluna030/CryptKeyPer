use super::xmss::Xmss;
use crate::errors::Result;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmss_full_cycle() -> Result<()> {
        // Create XMSS with height 2 (4 signatures) for faster testing
        let mut xmss = Xmss::new(2)?;
        
        // Test message
        let message = b"Hello, XMSS! This is a test message.";
        let mut msg_hash = [0u8; 32];
        msg_hash[..message.len().min(32)].copy_from_slice(&message[..message.len().min(32)]);
        
        // Sign the message
        let signature = xmss.sign(&msg_hash)?;
        
        // Verify the signature
        let is_valid = Xmss::verify(&msg_hash, &signature, &xmss.public_key)?;
        assert!(is_valid, "Signature should be valid");
        
        // Test that we have 3 signatures remaining
        assert_eq!(xmss.remaining_signatures(), 3);
        assert_eq!(xmss.current_index(), 1);
        
        Ok(())
    }

    #[test]
    fn test_multiple_signatures() -> Result<()> {
        let mut xmss = Xmss::new(2)?; // 4 signatures
        
        let messages = [
            b"First message ",
            b"Second message",
        ];
        
        let mut signatures = Vec::new();
        
        // Sign multiple messages
        for msg in &messages {
            let mut msg_hash = [0u8; 32];
            msg_hash[..msg.len().min(32)].copy_from_slice(&msg[..msg.len().min(32)]);
            
            let sig = xmss.sign(&msg_hash)?;
            signatures.push((msg_hash, sig));
        }
        
        // Verify all signatures
        for (i, (msg_hash, sig)) in signatures.iter().enumerate() {
            let is_valid = Xmss::verify(msg_hash, sig, &xmss.public_key)?;
            assert!(is_valid, "Signature {} should be valid", i);
        }
        
        assert_eq!(xmss.remaining_signatures(), 2); // 4 - 2 = 2
        
        Ok(())
    }

    #[test]
    fn test_signature_exhaustion() -> Result<()> {
        let mut xmss = Xmss::new(2)?; // Only 4 signatures
        
        let msg = [1u8; 32];
        
        // Use all signatures
        for _ in 0..4 {
            let _sig = xmss.sign(&msg)?;
        }
        
        // Try to sign one more - should fail
        let result = xmss.sign(&msg);
        assert!(result.is_err(), "Should fail when out of signatures");
        
        Ok(())
    }

    #[test]
    fn test_invalid_signature_verification() -> Result<()> {
        let mut xmss1 = Xmss::new(2)?;
        let xmss2 = Xmss::new(2)?;
        
        let msg = [42u8; 32];
        let signature = xmss1.sign(&msg)?;
        
        // Try to verify with wrong public key
        let is_valid = Xmss::verify(&msg, &signature, &xmss2.public_key)?;
        assert!(!is_valid, "Signature should not be valid with wrong public key");
        
        // Try to verify wrong message
        let wrong_msg = [43u8; 32];
        let is_valid = Xmss::verify(&wrong_msg, &signature, &xmss1.public_key)?;
        assert!(!is_valid, "Signature should not be valid for wrong message");
        
        Ok(())
    }

    #[test]
    fn test_height_validation() {
        // Test invalid heights
        assert!(Xmss::new(0).is_err(), "Height 0 should be invalid");
        assert!(Xmss::new(21).is_err(), "Height 21 should be invalid");
        
        // Test valid heights
        assert!(Xmss::new(1).is_ok(), "Height 1 should be valid");
        assert!(Xmss::new(10).is_ok(), "Height 10 should be valid");
        assert!(Xmss::new(20).is_ok(), "Height 20 should be valid");
    }
}