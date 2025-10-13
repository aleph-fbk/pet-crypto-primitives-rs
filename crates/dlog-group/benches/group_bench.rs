use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use dlog_group::{group::*, k256::*, p256::*, p384::*, ristretto::*};
use merlin::Transcript;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

criterion_main!(exp, mul, p_add, p_mul, rnd, p_rnd, p_inv);

criterion_group!(
    name = rnd;
    config = Criterion::default().sample_size(10);
    targets =
        ristretto_rnd,
        k256_rnd,
        p256_rnd,
        p384_rnd
);

criterion_group!(
    name = p_rnd;
    config = Criterion::default().sample_size(10);
    targets =
        ristretto_p_rnd,
        k256_p_rnd,
        p256_p_rnd,
        p384_p_rnd,
        hash_chacha,
        random_seed
);

criterion_group!(
    name = exp;
    config = Criterion::default().sample_size(10);
    targets =
        ristretto_exp,
        k256_exp,
        p256_exp,
        p384_exp
);

criterion_group!(
    name = mul;
    config = Criterion::default().sample_size(10);
    targets =
        ristretto_mul,
        k256_mul,
        p256_mul,
        p384_mul
);

criterion_group!(
    name = p_add;
    config = Criterion::default().sample_size(10);
    targets =
        ristretto_p_add,
        k256_p_add,
        p256_p_add,
        p384_p_add
);

criterion_group!(
    name = p_mul;
    config = Criterion::default().sample_size(10);
    targets =
        ristretto_p_mul,
        k256_p_mul,
        p256_p_mul,
        p384_p_mul
);

criterion_group!(
    name = p_inv;
    config = Criterion::default().sample_size(10);
    targets =
        ristretto_p_inv,
        k256_p_inv,
        p256_p_inv,
        p384_p_inv
);

macro_rules! p_rnd_bench {
    ($name:ident, $group:ty, $bench_name:ident) => {
        pub fn $bench_name(c: &mut Criterion) {
            c.bench_function(&format!("RUST-{}-p-rnd", $name.clone()), |b| {
                b.iter_batched(
                    || {
                        let rng = ChaChaRng::from_seed([5; 32]);
                        rng
                    },
                    |mut rng| <$group>::scalar_random(&mut rng),
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

macro_rules! rnd_bench {
    ($name:ident, $group:ty, $bench_name:ident) => {
        pub fn $bench_name(c: &mut Criterion) {
            c.bench_function(&format!("RUST-{}-g-rnd", $name.clone()), |b| {
                b.iter_batched(
                    || {
                        let rng = ChaChaRng::from_seed([5; 32]);
                        rng
                    },
                    |mut rng| <$group>::point_random(&mut rng),
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

macro_rules! p_inv_bench {
    ($name:ident, $group:ty, $bench_name:ident) => {
        pub fn $bench_name(c: &mut Criterion) {
            c.bench_function(&format!("RUST-{}-p-inv", $name.clone()), |b| {
                b.iter_batched(
                    || {
                        let mut rng = ChaChaRng::from_seed([5; 32]);
                        let e = <$group>::scalar_random(&mut rng);
                        e
                    },
                    |e| <$group>::scalar_inv(e),
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

macro_rules! p_mul_bench {
    ($name:ident, $group:ty, $bench_name:ident) => {
        pub fn $bench_name(c: &mut Criterion) {
            c.bench_function(&format!("RUST-{}-p-mul", $name.clone()), |b| {
                b.iter_batched(
                    || {
                        let mut rng = ChaChaRng::from_seed([5; 32]);
                        let e = <$group>::scalar_random(&mut rng);
                        let g = <$group>::scalar_random(&mut rng);
                        (e, g)
                    },
                    |(e, g)| g * &e,
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

macro_rules! p_add_bench {
    ($name:ident, $group:ty, $bench_name:ident) => {
        pub fn $bench_name(c: &mut Criterion) {
            c.bench_function(&format!("RUST-{}-p-add", $name.clone()), |b| {
                b.iter_batched(
                    || {
                        let mut rng = ChaChaRng::from_seed([5; 32]);
                        let h = <$group>::scalar_random(&mut rng);
                        let g = <$group>::scalar_random(&mut rng);
                        (h, g)
                    },
                    |(h, g)| g + &h,
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

macro_rules! exp_bench {
    ($name:ident, $group:ty, $bench_name:ident) => {
        pub fn $bench_name(c: &mut Criterion) {
            c.bench_function(&format!("RUST-{}-g-exp", $name.clone()), |b| {
                b.iter_batched(
                    || {
                        let mut rng = ChaChaRng::from_seed([5; 32]);
                        let e = <$group>::scalar_random(&mut rng);
                        let g = <$group>::generator();
                        (e, g)
                    },
                    |(e, g)| g * &e,
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

macro_rules! mul_bench {
    ($name:ident, $group:ty, $bench_name:ident) => {
        pub fn $bench_name(c: &mut Criterion) {
            c.bench_function(&format!("RUST-{}-g-mul", $name.clone()), |b| {
                b.iter_batched(
                    || {
                        let mut rng = ChaChaRng::from_seed([5; 32]);
                        let h = <$group>::point_random(&mut rng);
                        let g = <$group>::generator();
                        (h, g)
                    },
                    |(h, g)| g + &h,
                    BatchSize::SmallInput,
                )
            });
        }
    };
}

pub fn hash_chacha(c: &mut Criterion) {
    c.bench_function("RUST-hash-short", |b| {
        b.iter_batched(
            || {
                let rng_seed = <ChaChaRng as SeedableRng>::Seed::default();
                let mut source = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut source);
                rng_seed
            },
            ChaChaRng::from_seed,
            BatchSize::SmallInput,
        )
    });
}

pub fn random_seed(c: &mut Criterion) {
    c.bench_function("RUST-rnd-seed", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::thread_rng();
                let temp: u128 = rng.gen();
                let string = temp.to_string();
                let rng_seed = <ChaChaRng as SeedableRng>::Seed::default();
                let bytes = string.clone().into_bytes();
                let mut transcript = Transcript::new(b"test");
                transcript.append_message(b"append", &bytes);
                (bytes, transcript, rng_seed)
            },
            |(bytes, mut transcript, mut rng_seed)| {
                transcript.append_message(b"append", &bytes);
                transcript.challenge_bytes(b"c", &mut rng_seed)
            },
            BatchSize::SmallInput,
        )
    });
}

const RISTRETTO: &str = "Ristretto";
const K256: &str = "K256";
const P256: &str = "P256";
const P384: &str = "P384";

exp_bench!(RISTRETTO, RistrettoGroup, ristretto_exp);
exp_bench!(K256, K256Group, k256_exp);
exp_bench!(P256, P256Group, p256_exp);
exp_bench!(P384, P384Group, p384_exp);

mul_bench!(RISTRETTO, RistrettoGroup, ristretto_mul);
mul_bench!(K256, K256Group, k256_mul);
mul_bench!(P256, P256Group, p256_mul);
mul_bench!(P384, P384Group, p384_mul);

p_mul_bench!(RISTRETTO, RistrettoGroup, ristretto_p_mul);
p_mul_bench!(K256, K256Group, k256_p_mul);
p_mul_bench!(P256, P256Group, p256_p_mul);
p_mul_bench!(P384, P384Group, p384_p_mul);

p_add_bench!(RISTRETTO, RistrettoGroup, ristretto_p_add);
p_add_bench!(K256, K256Group, k256_p_add);
p_add_bench!(P256, P256Group, p256_p_add);
p_add_bench!(P384, P384Group, p384_p_add);

p_rnd_bench!(RISTRETTO, RistrettoGroup, ristretto_p_rnd);
p_rnd_bench!(K256, K256Group, k256_p_rnd);
p_rnd_bench!(P256, P256Group, p256_p_rnd);
p_rnd_bench!(P384, P384Group, p384_p_rnd);

rnd_bench!(RISTRETTO, RistrettoGroup, ristretto_rnd);
rnd_bench!(K256, K256Group, k256_rnd);
rnd_bench!(P256, P256Group, p256_rnd);
rnd_bench!(P384, P384Group, p384_rnd);

p_inv_bench!(RISTRETTO, RistrettoGroup, ristretto_p_inv);
p_inv_bench!(K256, K256Group, k256_p_inv);
p_inv_bench!(P256, P256Group, p256_p_inv);
p_inv_bench!(P384, P384Group, p384_p_inv);
