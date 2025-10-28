# User Guide
---
## Installation

`dlog-group` is published on crates.io. Add via Cargo:

```bash
cargo add dlog-group --features p256
```

Or add entries manually to your `Cargo.toml` (replace the version with the latest on crates.io):

```toml
[dependencies]
dlog-group = { version = "x.y.z", features = ["p256"] }
```
Available feature flags include: `"ristretto", "p256"`, `"k256"` and `"p384"`. 

## Usage
Once a group $\mathbb{G}$ is selected (following standard elliptic-curve conventions, $\mathbb{G}$ is considered an additive group), we can distinguish two main components:

1. **Points**: Elements of $\mathbb{G}$. If $P, Q \in \mathbb{G}$, then $P + Q \in \mathbb{G}$ as well. Operations on points (e.g. addition, scalar multiplication) are typically more expensive than on scalars.

2. **Scalars**: Elements of $\mathbb{Z}_n$, where $n$ is the order of the group $\mathbb{G}$. Scalars represent integer multipliers. For example, multiplying a point $P$ by $2$ (i.e., $[2]P$) is defined as $P + P$, and more generally $[r]P$ represents the sum of $P$ added to itself $r$-times.

These two structures support standard algebraic operations and are the basis for cryptographic schemes like Diffie–Hellman and digital signatures.

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