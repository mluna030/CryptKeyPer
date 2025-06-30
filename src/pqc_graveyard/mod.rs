//! # Post-Quantum Cryptography "Graveyard"
//! 
//! This module contains implementations of post-quantum cryptographic schemes that:
//! - Were eliminated from NIST standardization processes
//! - Show promise but need further research  
//! - Have interesting theoretical properties
//! - Could be valuable for specific use cases
//!
//! **⚠️ RESEARCH ONLY**: These implementations are for academic research and 
//! experimentation. They should NOT be used in production systems.

use crate::errors::Result;

pub mod lattice_based;
pub mod code_based;
pub mod multivariate;
pub mod isogeny_based;
pub mod symmetric_based;
pub mod graveyard_tour;

/// Trait for experimental post-quantum schemes
pub trait ExperimentalPQScheme {
    type PublicKey;
    type PrivateKey; 
    type Signature;
    type Error;
    
    /// Scheme name and status
    fn scheme_info() -> SchemeInfo;
    
    /// Key generation
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)>;
    
    /// Sign a message
    fn sign(message: &[u8], private_key: &Self::PrivateKey) -> Result<Self::Signature>;
    
    /// Verify a signature
    fn verify(message: &[u8], signature: &Self::Signature, public_key: &Self::PublicKey) -> Result<bool>;
    
    /// Performance characteristics
    fn performance_profile() -> PerformanceProfile;
    
    /// Security analysis
    fn security_analysis() -> SecurityAnalysis;
}

#[derive(Debug, Clone)]
pub struct SchemeInfo {
    pub name: &'static str,
    pub family: PQFamily,
    pub status: SchemeStatus,
    pub nist_round_eliminated: Option<u8>,
    pub year_proposed: u16,
    pub authors: Vec<&'static str>,
    pub paper_url: Option<&'static str>,
    pub implementation_notes: &'static str,
}

#[derive(Debug, Clone)]
pub enum PQFamily {
    LatticeBased,
    CodeBased,
    Multivariate,
    IsogenyBased,
    SymmetricKeyBased,
    HashBased,
    Other(String),
}

#[derive(Debug, Clone)]
pub enum SchemeStatus {
    /// Eliminated from NIST competition due to attacks
    Broken { attack_year: u16, attack_complexity: String },
    /// Eliminated due to large sizes or poor performance  
    Impractical { main_issue: String },
    /// Withdrawn by submitters during competition
    Withdrawn { reason: String },
    /// Actually made it through NIST competition
    NistWinner,
    /// Security weakened by new attacks but not completely broken
    WeakenedSecurity,
    /// Too complex or exotic for standardization
    TooExotic,
    /// Still being researched, shows promise
    UnderResearch,
    /// Interesting theoretical properties
    Theoretical,
    /// Could be practical with improvements
    NeedsOptimization,
}

#[derive(Debug, Clone)]
pub struct PerformanceProfile {
    pub key_size_bytes: (usize, usize), // (public, private)
    pub signature_size_bytes: usize,
    pub keygen_ops_estimate: u64,
    pub sign_ops_estimate: u64,
    pub verify_ops_estimate: u64,
    pub memory_usage_mb: f64,
}

#[derive(Debug, Clone)]
pub struct SecurityAnalysis {
    pub claimed_security_level: u16,
    pub known_attacks: Vec<AttackInfo>,
    pub security_assumptions: Vec<String>,
    pub quantum_security: bool,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct AttackInfo {
    pub attack_name: String,
    pub complexity: String,
    pub year_discovered: u16,
    pub paper_reference: String,
}