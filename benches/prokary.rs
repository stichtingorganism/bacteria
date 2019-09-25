//Bench Prokary

#[macro_use]
extern crate bencher;

use bencher::Bencher;
use prokary;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use rand::Rng;
use std::time::{Duration, SystemTime};

fn bench_prokary(b: &mut Bencher) {
    let nbmax = 63;
    let mut tbl = Vec::<(u64, Duration)>::new();
    let iterations = 1u64;

    b.bench_n(iterations, |b| {
        b.iter(|| {
            // Inner closure, the actual test
            for nb in 55..=nbmax {
                let mut rng: ThreadRng = thread_rng();
                let seed = rng.gen::<[u8; 32]>();
                let start = SystemTime::now();
                let proof = prokary::work(&seed, nb);
                let timing = start.elapsed().expect("timing");

                tbl.push((nb, timing));
                assert!(prokary::verify(&seed, &proof, nb));

                println!("Delay for {} bits: {:?}", nb, timing);
            }
        })
    });

    dbg!(&tbl);
}

benchmark_group!(benches, bench_prokary);
benchmark_main!(benches);
