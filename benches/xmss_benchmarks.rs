use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use cryptkeyper::{
    XmssParameterSet, 
    xmss::xmss::Xmss,
    xmss::xmss_optimized::XmssOptimized,
    parameters::WotsParameters,
};

fn benchmark_xmss_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("XMSS Key Generation");
    
    // Test different heights
    for height in [4, 6, 8, 10].iter() {
        group.bench_with_input(
            BenchmarkId::new("Original", height),
            height,
            |b, &height| {
                b.iter(|| {
                    let _xmss = Xmss::new(height).expect("Failed to create XMSS");
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("Optimized", height),
            height,
            |b, &height| {
                b.iter(|| {
                    let parameter_set = match height {
                        4 => XmssParameterSet::XmssSha256W16H10, // Close enough
                        6 => XmssParameterSet::XmssSha256W16H10,
                        8 => XmssParameterSet::XmssSha256W16H10,
                        10 => XmssParameterSet::XmssSha256W16H10,
                        _ => XmssParameterSet::XmssSha256W16H10,
                    };
                    let _xmss = XmssOptimized::new(parameter_set).expect("Failed to create optimized XMSS");
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_xmss_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("XMSS Signing");
    
    // Prepare test instances
    let mut xmss_original = Xmss::new(4).expect("Failed to create XMSS");
    let xmss_optimized = XmssOptimized::new(XmssParameterSet::XmssSha256W16H10)
        .expect("Failed to create optimized XMSS");
    
    let message = [42u8; 32];
    
    group.bench_function("Original", |b| {
        b.iter(|| {
            let _signature = xmss_original.sign(&message).expect("Signing failed");
        });
    });
    
    group.bench_function("Optimized", |b| {
        b.iter(|| {
            let _signature = xmss_optimized.sign(&message).expect("Optimized signing failed");
        });
    });
    
    group.finish();
}

fn benchmark_xmss_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("XMSS Verification");
    
    // Prepare test data
    let mut xmss_original = Xmss::new(4).expect("Failed to create XMSS");
    let xmss_optimized = XmssOptimized::new(XmssParameterSet::XmssSha256W16H10)
        .expect("Failed to create optimized XMSS");
    
    let message = [42u8; 32];
    let signature_original = xmss_original.sign(&message).expect("Signing failed");
    let signature_optimized = xmss_optimized.sign(&message).expect("Optimized signing failed");
    
    group.bench_function("Original", |b| {
        b.iter(|| {
            let _valid = Xmss::verify(
                &message,
                &signature_original,
                &xmss_original.public_key,
            ).expect("Verification failed");
        });
    });
    
    group.bench_function("Optimized", |b| {
        b.iter(|| {
            let _valid = XmssOptimized::verify(
                &message,
                &signature_optimized,
                &xmss_optimized.public_key,
            ).expect("Optimized verification failed");
        });
    });
    
    group.finish();
}

fn benchmark_parameter_sets(c: &mut Criterion) {
    let mut group = c.benchmark_group("Parameter Sets");
    
    let parameter_sets = [
        ("SHA256-W16-H10", XmssParameterSet::XmssSha256W16H10),
        ("SHA256-W16-H16", XmssParameterSet::XmssSha256W16H16),
        ("SHA512-W16-H10", XmssParameterSet::XmssSha512W16H10),
        ("SHAKE128-W16-H10", XmssParameterSet::XmssShake128W16H10),
    ];
    
    for (name, param_set) in parameter_sets.iter() {
        group.bench_with_input(
            BenchmarkId::new("KeyGen", name),
            param_set,
            |b, &param_set| {
                b.iter(|| {
                    let _xmss = XmssOptimized::new(param_set).expect("Failed to create XMSS");
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_wots_parameters(c: &mut Criterion) {
    let mut group = c.benchmark_group("WOTS+ Parameters");
    
    let param_sets = [
        XmssParameterSet::XmssSha256W16H10,
        XmssParameterSet::XmssSha512W16H10,
        XmssParameterSet::XmssShake128W16H10,
    ];
    
    for param_set in param_sets.iter() {
        let wots_params = param_set.wots_params();
        
        group.bench_function(&format!("base_w_{}", param_set.description()), |b| {
            let message = vec![42u8; param_set.output_size()];
            b.iter(|| {
                let _base_w = wots_params.message_to_base_w_with_checksum(&message);
            });
        });
    }
    
    group.finish();
}

fn benchmark_hash_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash Functions");
    
    let data = vec![42u8; 1024]; // 1KB of data
    
    use cryptkeyper::{Sha256HashFunction, Sha512HashFunction, Shake128HashFunction, HashFunction};
    
    let sha256 = Sha256HashFunction;
    let sha512 = Sha512HashFunction;
    let shake128 = Shake128HashFunction;
    
    group.bench_function("SHA256", |b| {
        b.iter(|| {
            let _hash = sha256.hash(&data);
        });
    });
    
    group.bench_function("SHA512", |b| {
        b.iter(|| {
            let _hash = sha512.hash(&data);
        });
    });
    
    group.bench_function("SHAKE128", |b| {
        b.iter(|| {
            let _hash = shake128.hash(&data);
        });
    });
    
    group.finish();
}

fn benchmark_cache_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("Cache Performance");
    
    let xmss = XmssOptimized::new(XmssParameterSet::XmssSha256W16H10)
        .expect("Failed to create optimized XMSS");
    
    let message = [42u8; 32];
    
    // Warm up cache
    for _ in 0..10 {
        let _ = xmss.sign(&message);
    }
    
    group.bench_function("With Cache", |b| {
        b.iter(|| {
            let _signature = xmss.sign(&message).expect("Signing failed");
        });
    });
    
    // Clear cache
    xmss.clear_caches();
    
    group.bench_function("Without Cache", |b| {
        b.iter(|| {
            let _signature = xmss.sign(&message).expect("Signing failed");
            xmss.clear_caches(); // Clear after each iteration
        });
    });
    
    group.finish();
}

fn benchmark_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Usage");
    
    group.bench_function("XMSS Original H4", |b| {
        b.iter(|| {
            let xmss = Xmss::new(4).expect("Failed to create XMSS");
            std::hint::black_box(xmss);
        });
    });
    
    group.bench_function("XMSS Optimized H10", |b| {
        b.iter(|| {
            let xmss = XmssOptimized::new(XmssParameterSet::XmssSha256W16H10)
                .expect("Failed to create optimized XMSS");
            std::hint::black_box(xmss);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_xmss_keygen,
    benchmark_xmss_signing,
    benchmark_xmss_verification,
    benchmark_parameter_sets,
    benchmark_wots_parameters,
    benchmark_hash_functions,
    benchmark_cache_performance,
    benchmark_memory_usage
);

criterion_main!(benches);