# Introduction
---

`dlog-sigma-primitives` is a Rust crate offering discrete logarithm based cryptographic building blocks over elliptic curve groups. Group arithmetic and encodings are abstracted via the companion `dlog-group` crate, so the same protocols can be instantiated over any supported group.

## Cryptographic model

Let $\mathbb{G}$ be a cyclic group of prime order $p$ with generator $g$, in this documentation we assume it written multiplicatively even if the implementation is written additively. Secrets and randomness are sampled from $\mathbb{Z}_p$; public elements live in $\mathbb{G}$. All statements and proofs in this crate are expressed as relations among discrete logarithms in $\mathbb{G}$. Security relies on the standard hardness of the discrete logarithm problem in $\mathbb{G}$ and, where required, on DDH style indistinguishability. Non-interactive proofs are obtained from Sigma protocols using the Fiat-Shamir transform in the random oracle model, with challenge values derived from domain separated transcripts using the `merlin` crate.

## Design goals

- **Composable**. Proofs share uniform traits so that complex statements can be built easily.
- **Explicit transcripts**. Every challenge is derived from a transcript with clear domain separation.
- **Group agnostic core**. Protocol logic is independent of a particular curve; concrete groups are supplied by `dlog-group` (e.g., P 256 via the `p256` feature).

