# Pedersen Commitments
---
Pedersen commitments [[TPP91]] let a committer bind to a value while keeping it hidden, and later open it for verification. The scheme has two core properties:

- Perfect hiding: the commitment leaks no information about the message.
- Computational binding: after committing, it is infeasible to open to a different message assuming the hardness of discrete logarithm in the chosen group.

[TPP91]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9  

## Mathematical setting

Let $\mathbb{G}$ be a cyclic group of prime order $p$ with two independent generators $g, h$ in $\mathbb{G}$. For binding, no party should know $\log_g(h)$. Messages and randomness are scalars in $\mathbb{Z}_p$.

To commit to $m \in \mathbb{Z}_p$ with randomness $r \in \mathbb{Z}_p$, compute
$$
Com = g^m \cdot h^r \in \mathbb{G}.
$$

The pair $(m, r)$ is an opening of $Com$. Verification checks
$$Com \stackrel{?}{=} g^m \cdot h^r.$$

Multi-message variant. For generators $g_1, ..., g_n$ and message vector $m = (m_1, ..., m_n)\in \mathbb{Z}_p^n$ with randomness $r \in \mathbb{Z}_p$, define
$$ 
Com = g_1^{m_1} \cdot ... \cdot g_n^{m_n} \cdot h^r.
$$

Correctness is immediate from group laws.

## Properties

- Perfect hiding. For fixed $m$, the distribution of $Com$ is uniform in $\mathbb{G}$ (because $h^r$ is uniform and independent of $m$). Hence $Com$ reveals nothing about $m$.

- Computational binding. If an adversary finds two distinct openings $(m, r) \neq (m', r')$ for the same commitment:
  $$g^m \cdot h^r = g^{m'} \cdot h^{r'}$$
  then $g^{m - m'} = h^{r' - r}$. If $r \neq r'$, this reveals $\log_g(h) = (m - m') / (r' - r) \in \mathbb{Z}_p$, contradicting the assumption that $\log_g(h)$ is unknown. If $r = r'$, then $m = m'$ follows immediately. Thus binding reduces to the discrete logarithm hardness in $\mathbb{G}$ together with the unknown-log relationship between $g$ and $h$.

- Additive homomorphism. For commitments $Com(m_1, r_1)$ and $Com(m_2, r_2)$,
  $Com(m_1, r_1) \cdot Com(m_2, r_2) = Com(m_1 + m_2, r_1 + r_2)$.
  The multi-message variant is likewise additively homomorphic.

These algebraic properties make Pedersen commitments ideal for zero-knowledge proofs about sums, equalities, and linear relations among hidden values.

## Applications

- Sealed values: commit now, reveal later (e.g., bids, choices, randomness beacons).
- Consistency checks: prove equality of hidden values across systems or that sums match.
- Privacy-preserving protocols: a standard building block for NIZKs, voting, mix-nets, and confidential transactions.

## Example

```rust,ignore

# use dlog_sigma_primitives::pedersen::commitment::{ExtendedPedersen, Parameters};
# use dlog_sigma_primitives::prelude::*;
# use core_rng::OsRng;
# 
# fn main() {
# let mut rng = OsRng;
// Choose a maximum supported message vector length and derive generators.
let list_len = 50;
let params = Parameters::<Curve>::new(list_len, &mut rng);

// Sample 40 messages (scalars) to commit.
let messages: Vec<<Curve as GroupScalar>::Scalar> =
  (0..40u64).map(|_| Curve::scalar_random(&mut rng)).collect();

// Variable-time, parallelized commitment (use const_commit for constant-time needs).
let (com, r) = ExtendedPedersen::var_commit(&params, &messages, &mut rng).unwrap().open();

// Verify with the provided opening (messages and randomness).
assert!(com
    .verify(&params, &messages, &r)
    .is_ok());
# }
```

Notes:
- Parameters should be sampled so that the generators have unknown discrete-log relation.
- ExtendedPedersen retains the randomness r, which is useful when composing zero-knowledge proofs. The bare Pedersen type contains only the commitment element Com.
- If constant-time behavior is required, prefer constant-time scalar multiplications (`const_commit`).