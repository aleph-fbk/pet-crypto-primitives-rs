# Zero-Knowledge Proofs

---

A **Zero-Knowledge Proof (ZKP)** is a cryptographic protocol that allows a prover to convince a verifier that a statement is true **without revealing any additional information** beyond the validity of the statement itself.

The concept was introduced in the 1980s by Goldwasser, Micali, and Rackoff [[GMR85]], who formalized the idea of proving statements while preserving secrecy. Since then, ZKPs have become a central tool in modern cryptography.

Every zero-knowledge proof must satisfy three core properties:

- **Completeness**: If the statement is true and both parties follow the protocol, the verifier will be convinced.

- **Soundness**: If the statement is false, no cheating prover can convince the verifier except with negligible probability.

- **Zero-Knowledge**: The proof reveals nothing beyond the truth of the statement. A simulator could produce an indistinguishable transcript without access to the secret.

This crate organizes all discrete-logarithm proofs around a single abstraction: **Sigma protocols**, and it is made non-interactive via **Fiat–Shamir** using `merlin` transcripts. This page explains the model, the protocol flow and what the `SigmaProtocol` trait guarantees. Concrete implemented proofs (Zero, Equality, OR, etc.) are merely *instances* of the same pattern.

The goal is simple: write each relation once in a uniform interface, get transcript handling for free, and compose proofs safely.

## What is a Sigma protocol?

A Sigma protocol is a 3-move public-coin protocol for proving knowledge of a witness $w$ to a public statement $x$ in some relation $R(w, x)$. The moves are:

1) **Commit**: the prover sends a commitment $t$ computed from fresh randomness $r$ and the statement $x$.
2) **Challenge**: the verifier samples and sends a random scalar $c$.
3) **Response**: the prover returns a response $z$ computed from $(r, w, c)$.

Finally, the verifier accepts if a fixed algebraic check holds, typically of the form

$$check(x, t, c, z) = true$$

For discrete logs, $t$ is a group element or tuple of elements, $c$ is a scalar in $\mathbb{Z}_p$, and $z$ is a linear combination of the witness and the commitment randomness.

A classic example, and fundamental building block is the Sigma-protocol for proving knowledge of a discrete logarithm:

- **Setup**: Let $\mathbb{G}$ be a cyclic group of prime order $p$ with generator $g$. The prover knows a secret $w \in \mathbb{Z}_p$ and the public value $y = g^w$. The statement is: *“I know $w$ such that $y = g^w$.”*

- **Protocol**: 
  1. **Commit**: The prover samples $r \in_R \mathbb{Z}_p$ and sends $t = g^r$ to the verifier.
  2. **Challenge**: The verifier sends a random $c \in_R \mathbb{Z}_p$.
  3. **Response**: The prover replies with $z = r + c \cdot w \pmod{p}$.

- **Verification**: The verifier checks
$
g^z \stackrel{?}{=} t \cdot y^c.
$

This protocol is complete, sound (under the hardness of discrete log), and zero-knowledge.

## From interactive to non-interactive: Fiat–Shamir

Interactive proofs are often turned into **non-interactive proofs** using the Fiat–Shamir heuristic [[FS86]]. Instead of receiving a random challenge from the verifier, the prover computes the challenge as a digest of the transcript and public information:

$$
c = hash(\text{context}, t, x),
$$

where $hash$ is a secure hash function modeled as a random oracle. This transformation makes proofs publishable and universally verifiable, and in practice almost all deployed systems rely on it.

The heuristic must be applied carefully. The entire context must be hashed to avoid malleability, and domain separation should be used so that distinct protocols cannot interfere with each other. Only modern cryptographic hash functions should be used. In private protocols with interaction (for example, credential issuance or authentication with an authority) a nonce may also be included to prevent replay attacks. In contrast, public proofs must avoid nonces to prevent linkability, and should instead rely on globally shared context.

Fiat–Shamir is both powerful and essential: it eliminates interaction, enables public verifiability, and upgrades honest-verifier zero-knowledge protocols to full zero-knowledge in the random oracle model, provided it is applied with the necessary care.

## The `SigmaProtocol` trait 

All proofs in this crate implement the same behavior so that Fiat–Shamir can be applied safely and uniformly. The contract below is the minimum needed to make non-interactive Sigma protocols correct by construction, composable, and auditable.

- `Public(x)`: Borrowed view of the entire public statement with a fixed encoding order. Deterministic absorption of $x$ ensures consistent transcript context and prevents malleability.

- `Witness(w)`: The prover's secret (e.g., exponent, opening, encryption randomness). In order to avoid disclosure it is always zeroized on drop.

- `State`: Ephemeral randomness used to form commitments. It is consumed during `complete()` to prevent reuse and ensure fresh commitments in each proof instance.

- `Proof`: Minimal serialized object containing what the verifier needs to replay commitments and verify the relation.

- Protocol methods (canonical order):
  1) `absorb_public(x, transcript)`: absorb $x$ in the transcript.
  2) `init(x, rng) -> State`: sample fresh ephemeral randomness.
  3) `commit(x, state, w, transcript)`: append all commitments; no challenge yet.
  4) `complete(state, w, transcript) -> Proof`: derive c from the transcript, compute responses, serialize proof, consume state.
  5) `update_transcript(proof, transcript)`: verifier-side replay of commitments from the proof.
  6) `verify_relation(x, proof, transcript)`: recompute c and check the algebraic equation.

- One-shot helpers, to enforce the canonical sequence and reduce misuse in callers:
  - `prove(x, w, transcript, rng)`
  - `verify(x, proof, transcript)`

### Transcript

- Each protocol sets a unique, immutable `DOMAIN`.
- Prover and verifier must call `start_proof(DOMAIN, public, absorb_public)` before any other transcript operation.
- `absorb_public` appends the entire public statement once in a fixed order.
- Commitments are then appended by `commit`. The challenge is derived only after all commitments have been absorbed.
- The verifier must exactly mirror `commit` through `update_transcript` before deriving the challenge.

### Proof helper trait

Every proof struct implements `Proof` by setting `type Protocol = ...`. This exposes ergonomic one-shot helpers hiding the `Transcript` object while enforcing canonical order. For advanced use, call the protocol methods directly and pass an explicit transcript.

```rust, ignore
// Prover side
let proof = Zero::<Curve>::prove(public, &witness, &mut rng);

// Verifier side
proof.verify(public)?;
```
## Applications

Zero-knowledge proofs are widely used whenever one must **prove correctness without revealing the underlying secret**. Common examples include:

- **Well-formedness proofs**, showing that encrypted or committed values lie in a valid set.
- **Consistency checks**, ensuring two hidden values are equal or satisfy a relation.
- **Privacy-preserving protocols**, core of the classical scope for ZKPs such as anonymous credentials and voting systems. 

## Supported Proofs

This library includes a collection of zero-knowledge proofs that can be used as **modular building blocks** in cryptographic systems. Each proof enforces a specific algebraic property (e.g., equality of discrete logs, correct shuffling, or consistency with a reference value) and can be combined with others to enforce more complex constraints.

The table below summarizes the supported proofs, the guarantees they provide, and a representative application in e-voting systems:

| Proof Type                | What it Shows                                                                 | Example Application in E-Voting                |
|----------------------------|-------------------------------------------------------------------------------|------------------------------------------------|
| **Zero** | A ciphertext encodes the value zero | Building block for ballot validity and consistency checks |
| **Disjunctive (OR)**      | A ciphertext encodes one value from a predefined set               | Proving each selection is either 0 or 1        |
| **Exponential (Exp)**     | Knowledge of the plaintext exponent in an exponential ElGamal ciphertext       | Encoding and proving selections as exponents   |
| **Equality**              | Two group elements share the same discrete logarithm w.r.t. different bases   | Linking related ciphertexts for consistency    |
| **Plaintext**             | Prover knows the plaintext inside a ciphertext (without revealing it)         | Ensuring the voter knows the vote they cast    |
| **Not Identity (NotId)**  | A ciphertext does not encrypt the group identity   | Preventing malformed or trivial ballot fields  |
| **Verifiable Decryption** | A ciphertext has been correctly decrypted under a public key scheme           | Publicly auditable tallying                    |
| **Designated Verifier**   | Proof validity can be checked only by a specific verifier with secret data     | Restricting credential checks to the voter   |
| **Shuffle**               | A list of ciphertexts was permuted and re-randomized correctly                | Verifiable mixing of ballots in anonymization  |

## Example
We show how to generate and verify a `Zero` proof. Examples for the other proofs are included in the API documentation. Thanks to the trait implementation, most proofs follows the exact same pattern.

```rust, ignore
# use dlog_sigma_primitives::prelude::*;
# use dlog_sigma_primitives::proofs::zero::{ZeroProtocol, ZeroPublicBorrowed};
# let mut rng = OsRng;
# fn main() {
let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
let (_sk, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();

// Zero plaintext (group identity)
let (ct, r) = pk.encrypt(Curve::identity(), &params, &mut rng).into_tuple();

let public = ZeroPublicBorrowed::new(&pk, &params, &ct);

// Prover
let mut tr_p = Transcript::new(b"example");
let proof = ZeroProtocol::prove(public, &r, &mut tr_p, &mut rng);

// Verifier
let mut tr_v = Transcript::new(b"example");
ZeroProtocol::verify(public, &proof, &mut tr_v).expect("verification");
# }
```
<!--
## Performance

I am not too sure about inserting the performance here, maybe it is better to simply mention the benchmarks
in the develop guide section, if someone what to make a comparison.


| Proof    [ms]   | Generation | Verification     | 
|-----------------|-----------|----------|
| Zero            | 0.0847    | 0.1608   | 
| NotId           | 0.3628    | 0.372    |
| LogEq           | 0.111     | 0.2106   |
| Plaintext       | 0.1282    | 0.2067   |
| Or (0, 1)       | 0.2939    | 0.3797   |
| Shuffle ($10^5$)   | 1155.3  | 1517.9  |   
-->

[FS86]: https://link.springer.com/chapter/10.1007/3-540-47721-7_12
[CS97]: https://crypto.ethz.ch/publications/files/CamSta97b.pdf
[GMR85]: https://dl.acm.org/doi/10.1145/22145.22178
