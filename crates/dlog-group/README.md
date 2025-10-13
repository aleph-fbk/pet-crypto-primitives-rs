# dlog-group

A unified wrapper around different **prime-order cryptographic groups** where the [discrete log][DLP] (DL),
[computational Diffie–Hellman][CDH] (CDH), and [decisional Diffie–Hellman][DDH] (DDH) problems are believed
to be hard.  

This crate provides a common trait-based interface over popular RustCrypto elliptic-curve crates,
plus [Ristretto](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html).

[DDH]: https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption
[CDH]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_problem
[DLP]: https://en.wikipedia.org/wiki/Discrete_logarithm

## Supported groups
Currently supports the following Elliptic-Curve Groups:
[`ristretto`] used by default, [`p256`], [`k256`] and [`p384`] enabled by features.

[`ristretto`]: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html
[`p256`]: https://docs.rs/p256/latest/p256/
[`k256`]: https://docs.rs/k256/latest/k256/
[`p384`]: https://docs.rs/p384/latest/p384/

## Installation

```toml
[dependencies]
dlog-groups = "0.1"           # replace with the latest version

# Optional features:
# dlog-groups = { version = "0.1", features = ["p256", "k256", "p384"] }
```

## Example
Import the ristretto backend and the Trait specifications
``` 
use dlog_group::{
    ristretto::{RistrettoGroup}, 
    group::{GroupPoint, GroupScalar}
};
use rand;
``` 
Generete an `rng` for a random scalar `r`
``` 
let mut rng = rand::thread_rng();
```         
Do the following simple check $g = \dfrac{g^{1 + r}}{g^r}$
``` 
let group_generator = RistrettoGroup::generator();
let r = RistrettoGroup::scalar_random(&mut rng);

let group_pow = group_generator * &r;
let group_mul = group_generator + &group_pow;
let group_div = group_mul - &group_pow;
assert_eq!(group_div, group_generator);
```

## Documentation
Use `cargo doc --all-features --open` to generate the crate documentation and open it.


## License

Licensed under either of [Apache License Version 2.0](LICENSE-APACHE), or [MIT license](LICENSE-MIT).


## Acknowledgments

This work has been supported by the joint laboratory between the Bruno Kessler Foundation (FBK) and the Italian Government Printing Office and Mint (IPZS).