//! Interactive tour of the PQC Graveyard
//! 
//! This module provides educational demonstrations of why various
//! post-quantum schemes were eliminated from standardization.

use super::*;
use crate::errors::Result;
use std::collections::HashMap;

/// Educational tour guide for the PQC Graveyard
pub struct GraveyardTour {
    schemes: HashMap<String, Box<dyn SchemeAnalyzer>>,
}

/// Trait for analyzing schemes in the graveyard
pub trait SchemeAnalyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn family(&self) -> PQFamily;
    fn elimination_story(&self) -> String;
    fn lessons_learned(&self) -> Vec<String>;
    fn performance_vs_security_tradeoff(&self) -> TradeoffAnalysis;
}

#[derive(Debug, Clone)]
pub struct TradeoffAnalysis {
    pub security_score: f64,      // 0-10 scale
    pub performance_score: f64,   // 0-10 scale  
    pub practicality_score: f64,  // 0-10 scale
    pub innovation_score: f64,    // 0-10 scale
    pub fatal_flaw: Option<String>,
}

impl GraveyardTour {
    pub fn new() -> Self {
        let mut tour = GraveyardTour {
            schemes: HashMap::new(),
        };
        
        // Add analyzers for each scheme family
        tour.add_scheme_analyzers();
        tour
    }
    
    fn add_scheme_analyzers(&mut self) {
        // Isogeny-based schemes
        self.schemes.insert(
            "SIKE".to_string(), 
            Box::new(SikeAnalyzer)
        );
        
        // Multivariate schemes
        self.schemes.insert(
            "Rainbow".to_string(), 
            Box::new(RainbowAnalyzer)
        );
        
        // Code-based schemes
        self.schemes.insert(
            "BIKE".to_string(), 
            Box::new(BikeAnalyzer)
        );
        
        // Lattice-based schemes
        self.schemes.insert(
            "TESLA".to_string(), 
            Box::new(TeslaAnalyzer)
        );
        
        // Symmetric schemes
        self.schemes.insert(
            "PICNIC".to_string(), 
            Box::new(PicnicAnalyzer)
        );
    }
    
    /// Get all schemes organized by why they were eliminated
    pub fn schemes_by_fate(&self) -> HashMap<String, Vec<String>> {
        let mut by_fate = HashMap::new();
        
        by_fate.insert("Cryptographically Broken".to_string(), vec![
            "SIKE - Castryck-Decru attack".to_string(),
            "ROLLO - Algebraic attacks".to_string(),
            "FISH - Polynomial-time break".to_string(),
        ]);
        
        by_fate.insert("Impractically Large".to_string(), vec![
            "Rainbow - 60KB+ public keys".to_string(),
            "Classic McEliece - 1.3MB keys".to_string(),
            "PICNIC - 200KB signatures".to_string(),
            "TESLA - 3KB+ signatures".to_string(),
        ]);
        
        by_fate.insert("Side-Channel Vulnerable".to_string(), vec![
            "BIKE - Timing attacks on decoding".to_string(),
            "HQC - Implementation vulnerabilities".to_string(),
        ]);
        
        by_fate.insert("Too Complex/Exotic".to_string(), vec![
            "GeMSS - Complex HFE variant".to_string(),
            "LUOV - Succumbed to MinRank".to_string(),
        ]);
        
        by_fate.insert("Actually Survived".to_string(), vec![
            "SPHINCS+ - Stateless hash-based winner".to_string(),
            "Classic McEliece - Conservative choice".to_string(),
        ]);
        
        by_fate
    }
    
    /// Timeline of PQC failures and discoveries
    pub fn failure_timeline(&self) -> Vec<TimelineEvent> {
        vec![
            TimelineEvent {
                year: 2017,
                event: "NIST PQC Competition begins".to_string(),
                significance: "69 submissions entered the race".to_string(),
            },
            TimelineEvent {
                year: 2019,
                event: "Round 1 eliminations".to_string(),
                significance: "43 schemes eliminated, many due to breaks".to_string(),
            },
            TimelineEvent {
                year: 2019,
                event: "FISH broken".to_string(),
                significance: "Algebraic attack shows symmetric-key signature challenges".to_string(),
            },
            TimelineEvent {
                year: 2020,
                event: "Round 2 eliminations".to_string(),
                significance: "Practical considerations eliminate more schemes".to_string(),
            },
            TimelineEvent {
                year: 2020,
                event: "ROLLO broken".to_string(),
                significance: "Rank-based cryptography proves vulnerable".to_string(),
            },
            TimelineEvent {
                year: 2021,
                event: "Round 3 and beyond".to_string(),
                significance: "Side-channel attacks eliminate more candidates".to_string(),
            },
            TimelineEvent {
                year: 2022,
                event: "SIKE catastrophically broken".to_string(),
                significance: "Castryck-Decru attack destroys isogeny-based crypto".to_string(),
            },
            TimelineEvent {
                year: 2024,
                event: "Standards published".to_string(),
                significance: "Only a handful of schemes survive the gauntlet".to_string(),
            },
        ]
    }
    
    /// Lessons learned from the graveyard
    pub fn lessons_learned(&self) -> LessonsLearned {
        LessonsLearned {
            cryptographic_lessons: vec![
                "New mathematical foundations need decades of analysis".to_string(),
                "Exotic approaches often hide unexpected weaknesses".to_string(),
                "Side-channel resistance is as important as mathematical security".to_string(),
                "Conservative parameter choices are essential".to_string(),
            ],
            
            engineering_lessons: vec![
                "Key and signature sizes matter enormously for adoption".to_string(),
                "Implementation complexity leads to vulnerabilities".to_string(),
                "Performance bottlenecks make schemes impractical".to_string(),
                "Constant-time implementations are mandatory".to_string(),
            ],
            
            standardization_lessons: vec![
                "Public competitions reveal weaknesses faster".to_string(),
                "Diversity in approaches is valuable until it isn't".to_string(),
                "Perfect is the enemy of good enough".to_string(),
                "Conservative choices win in standards battles".to_string(),
            ],
            
            quantum_lessons: vec![
                "Quantum computers are coming, but slowly".to_string(),
                "Classical attacks evolve faster than quantum computers".to_string(),
                "Post-quantum doesn't mean post-classical".to_string(),
                "Hybrid approaches may be necessary during transition".to_string(),
            ],
        }
    }
    
    /// Educational comparison of schemes
    pub fn scheme_comparison(&self) -> Vec<SchemeComparison> {
        vec![
            SchemeComparison {
                name: "SIKE vs CRYSTALS-Kyber",
                winner: "Kyber",
                reason: "SIKE had tiny keys but was completely broken".to_string(),
                lesson: "Mathematical novelty can be dangerous".to_string(),
            },
            SchemeComparison {
                name: "Rainbow vs CRYSTALS-Dilithium", 
                winner: "Dilithium",
                reason: "Rainbow had massive public keys (60KB vs 1.3KB)".to_string(),
                lesson: "Size matters in practical cryptography".to_string(),
            },
            SchemeComparison {
                name: "PICNIC vs SPHINCS+",
                winner: "SPHINCS+",
                reason: "PICNIC signatures were 10x larger".to_string(),
                lesson: "Even exotic schemes must be practical".to_string(),
            },
            SchemeComparison {
                name: "XMSS vs SPHINCS+",
                winner: "Both (different use cases)",
                reason: "XMSS is stateful but efficient, SPHINCS+ is stateless but slow".to_string(),
                lesson: "Different problems need different solutions".to_string(),
            },
        ]
    }
    
    /// Generate a detailed report on a specific scheme
    pub fn scheme_autopsy(&self, scheme_name: &str) -> Option<SchemeAutopsy> {
        self.schemes.get(scheme_name).map(|analyzer| {
            SchemeAutopsy {
                name: analyzer.name().to_string(),
                family: analyzer.family(),
                cause_of_death: analyzer.elimination_story(),
                lessons: analyzer.lessons_learned(),
                tradeoffs: analyzer.performance_vs_security_tradeoff(),
                epitaph: self.generate_epitaph(analyzer.as_ref()),
            }
        })
    }
    
    fn generate_epitaph(&self, analyzer: &dyn SchemeAnalyzer) -> String {
        match analyzer.name() {
            "SIKE" => "Here lies SIKE: Small keys, big dreams, fatal flaw".to_string(),
            "Rainbow" => "Here lies Rainbow: Beautiful math, massive keys".to_string(),
            "BIKE" => "Here lies BIKE: Fast and small, but timing gave it away".to_string(),
            "PICNIC" => "Here lies PICNIC: Zero-knowledge proofs, infinite signatures".to_string(),
            _ => format!("Here lies {}: Another casualty of the quantum wars", analyzer.name()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub year: u16,
    pub event: String,
    pub significance: String,
}

#[derive(Debug, Clone)]
pub struct LessonsLearned {
    pub cryptographic_lessons: Vec<String>,
    pub engineering_lessons: Vec<String>,
    pub standardization_lessons: Vec<String>,
    pub quantum_lessons: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SchemeComparison {
    pub name: String,
    pub winner: String,
    pub reason: String,
    pub lesson: String,
}

#[derive(Debug, Clone)]
pub struct SchemeAutopsy {
    pub name: String,
    pub family: PQFamily,
    pub cause_of_death: String,
    pub lessons: Vec<String>,
    pub tradeoffs: TradeoffAnalysis,
    pub epitaph: String,
}

// Individual scheme analyzers
struct SikeAnalyzer;
impl SchemeAnalyzer for SikeAnalyzer {
    fn name(&self) -> &'static str { "SIKE" }
    fn family(&self) -> PQFamily { PQFamily::IsogenyBased }
    
    fn elimination_story(&self) -> String {
        "SIKE seemed perfect: tiny keys, solid math, years of analysis. Then in July 2022, \
         Castryck and Decru published a devastating attack that broke it in hours on a laptop. \
         The attack exploited deep mathematical properties of supersingular isogenies that \
         even experts missed for years.".to_string()
    }
    
    fn lessons_learned(&self) -> Vec<String> {
        vec![
            "Newer mathematical foundations are riskier".to_string(),
            "Expert analysis can miss fundamental flaws".to_string(),
            "Compact schemes often hide complexity".to_string(),
            "Diversity in PQC approaches is essential".to_string(),
        ]
    }
    
    fn performance_vs_security_tradeoff(&self) -> TradeoffAnalysis {
        TradeoffAnalysis {
            security_score: 0.0, // Completely broken
            performance_score: 9.0, // Excellent performance
            practicality_score: 9.0, // Perfect key sizes
            innovation_score: 10.0, // Highly innovative
            fatal_flaw: Some("Castryck-Decru polynomial-time attack".to_string()),
        }
    }
}

struct RainbowAnalyzer;
impl SchemeAnalyzer for RainbowAnalyzer {
    fn name(&self) -> &'static str { "Rainbow" }
    fn family(&self) -> PQFamily { PQFamily::Multivariate }
    
    fn elimination_story(&self) -> String {
        "Rainbow had solid security and fast operations, but its public keys were enormous - \
         60KB to 1.8MB depending on security level. In a world of IoT devices and mobile apps, \
         nobody wanted to store megabyte-sized public keys.".to_string()
    }
    
    fn lessons_learned(&self) -> Vec<String> {
        vec![
            "Key sizes are a first-class constraint".to_string(),
            "Mathematical elegance doesn't guarantee practicality".to_string(),
            "Mobile and IoT use cases drive requirements".to_string(),
            "Storage costs matter in real systems".to_string(),
        ]
    }
    
    fn performance_vs_security_tradeoff(&self) -> TradeoffAnalysis {
        TradeoffAnalysis {
            security_score: 8.0, // Good security
            performance_score: 8.0, // Fast operations
            practicality_score: 2.0, // Terrible key sizes
            innovation_score: 7.0, // Solid multivariate approach
            fatal_flaw: Some("Impractically large public keys".to_string()),
        }
    }
}

struct BikeAnalyzer;
impl SchemeAnalyzer for BikeAnalyzer {
    fn name(&self) -> &'static str { "BIKE" }
    fn family(&self) -> PQFamily { PQFamily::CodeBased }
    
    fn elimination_story(&self) -> String {
        "BIKE had reasonable key sizes and good performance, but succumbed to timing attacks \
         on its bit-flipping decoder. The attacks exploited the variable-time nature of the \
         error correction algorithm to extract private key information.".to_string()
    }
    
    fn lessons_learned(&self) -> Vec<String> {
        vec![
            "Constant-time implementation is mandatory".to_string(),
            "Side-channel attacks are as dangerous as mathematical ones".to_string(),
            "Error correction can leak information".to_string(),
            "Implementation security is part of cryptographic security".to_string(),
        ]
    }
    
    fn performance_vs_security_tradeoff(&self) -> TradeoffAnalysis {
        TradeoffAnalysis {
            security_score: 3.0, // Vulnerable to side-channels
            performance_score: 7.0, // Good performance
            practicality_score: 7.0, // Reasonable sizes
            innovation_score: 6.0, // Interesting code-based approach
            fatal_flaw: Some("Timing attacks on bit-flipping decoder".to_string()),
        }
    }
}

struct TeslaAnalyzer;
impl SchemeAnalyzer for TeslaAnalyzer {
    fn name(&self) -> &'static str { "TESLA" }
    fn family(&self) -> PQFamily { PQFamily::LatticeBased }
    
    fn elimination_story(&self) -> String {
        "TESLA had strong security based on Ring-LWE, but its signatures were over 3KB - \
         far too large for most applications. While secure, the practical overhead made \
         it unsuitable for real-world deployment.".to_string()
    }
    
    fn lessons_learned(&self) -> Vec<String> {
        vec![
            "Signature size is critical for adoption".to_string(),
            "Security alone is not enough".to_string(),
            "Bandwidth costs matter in networked applications".to_string(),
            "Trade-offs must balance multiple constraints".to_string(),
        ]
    }
    
    fn performance_vs_security_tradeoff(&self) -> TradeoffAnalysis {
        TradeoffAnalysis {
            security_score: 8.0, // Strong security
            performance_score: 6.0, // Decent performance
            practicality_score: 3.0, // Large signatures
            innovation_score: 5.0, // Standard lattice approach
            fatal_flaw: Some("Signature sizes over 3KB".to_string()),
        }
    }
}

struct PicnicAnalyzer;
impl SchemeAnalyzer for PicnicAnalyzer {
    fn name(&self) -> &'static str { "PICNIC" }
    fn family(&self) -> PQFamily { PQFamily::SymmetricKeyBased }
    
    fn elimination_story(&self) -> String {
        "PICNIC was theoretically fascinating - using zero-knowledge proofs to create signatures \
         from symmetric primitives. But the signatures were 200KB+, making them completely \
         impractical for any real application.".to_string()
    }
    
    fn lessons_learned(&self) -> Vec<String> {
        vec![
            "Theoretical beauty doesn't guarantee practicality".to_string(),
            "Zero-knowledge proofs can be expensive".to_string(),
            "Novel approaches need better efficiency".to_string(),
            "200KB signatures won't work in the real world".to_string(),
        ]
    }
    
    fn performance_vs_security_tradeoff(&self) -> TradeoffAnalysis {
        TradeoffAnalysis {
            security_score: 8.0, // Solid security
            performance_score: 2.0, // Very slow
            practicality_score: 1.0, // Completely impractical
            innovation_score: 10.0, // Highly innovative approach
            fatal_flaw: Some("Massive signature sizes (200KB+)".to_string()),
        }
    }
}