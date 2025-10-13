# User Guide
---
## Installation
Currently, `dlog-group` is not published on [crates.io](https://crates.io/), so in order to use it you must download the library locally and reference it in your Cargo.toml:
```toml
[dependencies]
dlog-group = {path = ./your-path-to/dlog-group}
```
By default, only the `RistrettoGroup` backend is compiled. Additional groups are available behind feature flags. To enable them, specify the desired features:
```toml
[dependencies]
dlog-group = {path = ./your-path-to/dlog-group, features = ["p256"]}
```
Available feature flags include: `"p256"`, `"k256"` and `"p384"`.

## Usage
Once a group $\mathbb{G}$ is selected (following standard elliptic-curve conventions, $\mathbb{G}$ is considered an additive group), we can distinguish two main components:

1. **Points**: Elements of $\mathbb{G}$. If $P, Q \in \mathbb{G}$, then $P + Q \in \mathbb{G}$ as well. Operations on points (e.g. addition, scalar multiplication) are typically more expensive than on scalars.

2. **Scalars**: Elements of $\mathbb{Z}_n$, where $n$ is the order of the group $\mathbb{G}$. Scalars represent integer multipliers. For example, multiplying a point $P$ by $2$ (i.e., $[2]P$) is defined as $P + P$, and more generally $[r]P$ represents the sum of $P$ added to itself $r$-times.

These two structures support standard algebraic operations and are the basis for cryptographic schemes like Diffie–Hellman and digital signatures.

To view a complete list of available functionalities, you can compile and open the complete API documentation with:
```bash
cargo doc --all-features --open
```

### Example

First, we import a backend implementation (in this case, `RistrettoGroup`) as well as the traits `GroupPoint` and `GroupScalar`, which provide operations over points and scalars, respectively:
```rust, ignore
use dlog_group::{
    ristretto::{RistrettoGroup}, 
    group::{GroupPoint, GroupScalar}
};
```
We additionally import the [rand](https://crates.io/crates/rand) crate to generate a random seed (`rng`) which we are going to use to generate a scalar `r`.
```rust, ignore
use rand;
let mut rng = rand::thread_rng();
```
Finally, let’s use the standard generator $G$ of the `RistrettoGroup`, perform some basic operations, and verify that the following holds: 
$$
G = [1 + r]G - [r]{G}
$$
```rust, ignore
let G = RistrettoGroup::generator();
let r = RistrettoGroup::scalar_random(&mut rng);

let r_G = G * &r;
let r1_G = G + &r_G;

assert_eq!(r1_G - &r_G, G);
```

## Performance

We report the timings of the main operations for each supported curve, where $P, Q \in \mathbb{G}$ and $a, b \in \mathbb{Z}_n$. Note that performance is not the only metric to consider when choosing a curve, for example, P384 offers a higher security level (in bits) compared to the others. The data below was collected on an Intel® Core™ Ultra 7 165H and is represented in nanoseconds (ns).


| Operation       | Ristretto | K256     | P256     | P384      |
|-----------------|-----------|----------|----------|-----------|
| $[r]P$          | 24,168    | 29,407   | 90,251   | 379,02    |
| $P + Q$         | 139.93    | 172.77   | 265.80   | 762.73    |
| $a + b$         | 17.263    | 8.7378   | 8.8894   | 14.125    |
| $a \cdot b$     | 60.127    | 24.545   | 45.440   | 46.204    |