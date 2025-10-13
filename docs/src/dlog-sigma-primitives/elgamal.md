# Modified ElGamal

---

Modified ElGamal is a public key encryption scheme over a cyclic group of prime order that introduces a two-dimensional secret key and a three-component ciphertext. The change preserves the core guarantees of classical ElGamal (IND-CPA under DDH, rerandomizability, and homomorphism) while making the ciphertext structure more convenient for zero-knowledge proofs, shuffles, and threshold-style workflows.

## Mathematical setting

Let $\mathbb{G}$ be a cyclic group of prime order $p$ with independent generators $g_1, g_2 \in \mathbb{G}$.

- Secret key: $(x_1, x_2) \in \mathbb{Z}_p^2$ sampled uniformly at random.
- Public key: $h = g_1^{x_1} \cdot g_2^{x_2} \in \mathbb{G}$.

Encryption of $m \in \mathbb{G}$:

1. Sample $r \in \mathbb{Z}_p$ uniformly at random.
2. Output ciphertext $C = (A, B, C_3)$ where
   $A = g_1^{r},  B = g_2^{r},  C_3 = h^{r} \cdot m.$

Decryption with secret key $(x_1, x_2)$:
$$m = C_3 \cdot (A^{x_1} \cdot B^{x_2})^{-1}.$$

Correctness follows since:
$$A^{x_1} \cdot B^{x_2} = (g_1^{r})^{x_1} \cdot (g_2^{r})^{x_2} = (g_1^{x_1} \cdot g_2^{x_2})^{r} = h^{r}.$$

### Homomorphism

For any two ciphertexts $C(m_1; r_1)$ and $C(m_2; r_2)$,
$$C(m_1; r_1) \cdot C(m_2; r_2) = C(m_1 \cdot m_2; r_1 + r_2).$$
Thus Modified ElGamal is multiplicatively homomorphic.

When messages are represented in the exponent, i.e., $m = g^{a}$ for a third fixed generator $g$, then
$$C(g^{a_1}) \cdot C(g^{a_2}) = C(g^{a_1 + a_2}),$$
which induces additive homomorphism on exponents. Recovering $a$ from $g^{a}$ requires solving a discrete logarithm and is feasible only for small message domains.

### Rerandomization

Given $C(m; r) = (A, B, C_3)$, any party can produce a distribution-identical ciphertext on the same plaintext by sampling $z$ in $\mathbb{Z}_p$ and outputting
$$(A \cdot g_1^{z}, B \cdot g_2^{z}, C_3 \cdot h^{z}) = C(m; r + z).$$
Rerandomization preserves correctness and hides $r$.

## Applications

- Verifiable shuffles and mix-nets: ciphertexts can be permuted and rerandomized while preserving plaintexts.
- Threshold workflows: the split structure of the secret key and the explicit randomness terms simplify share verifications.
- Privacy-preserving systems: voting, sealed-bid auctions, credential systems, and any setting that benefits from efficient NIZKs over ElGamal relations.

[JCJ02]: https://eprint.iacr.org/2002/165  
[DDH]: https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption

## Example 

The crate is generic over a group backend. For documentation builds, select exactly one backend feature for the library (for example, `p256` or `ristretto`). The alias `Curve` refers to the selected backend in this build.

```rust,ignore
# // In Cargo.toml of this doc build:
# // dlog-sigma-primitives = { version = "x.y.z", features = ["p256"] }
# 
# use rand_core::OsRng;
# use dlog_sigma_primitives::prelude::*;
# 
# // The library exposes a concrete backend alias selected by features:
# // type Curve = dlog_group::<backend>::Group;
# // All APIs remain generic; Curve is provided for convenience.
# 
# fn main() {
# let mut rng = OsRng;
// (sk, pk) sampled in the selected Curve
let params = ElGamalParams::<Curve>::new(&mut rng);
let (sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();

// Sample a random message
let m = Curve::generator() * Curve::scalar_random(&mut rng);

// Encrypt and decrypt
let (ct, _r) = pk.encrypt(m, &params, &mut rng).into_tuple();

let m_dec = sk.decrypt(&ct);

assert_eq!(m, m_dec);
# }
```