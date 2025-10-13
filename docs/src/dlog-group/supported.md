# Introduction
---
`dlog-group` is a simple rust wrapper around different prime-order groups implementations where
the [decisional Diffie–Hellman][DDH] (DDH), [computational Diffie–Hellman][CDH] (CDH)
and [discrete log][DLP] (DL) problems are believed to be hard.

The purpose of this wrapper is to make it easy to switch between different group implementations. This can be useful for improving performance, adjusting security levels, or following new standards. By using a common interface, `dlog-group` lets you change the underlying group without rewriting your code, and makes it easy to compare how an implementation perform under different core operations.

[DDH]: https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption
[CDH]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_problem
[DLP]: https://en.wikipedia.org/wiki/Discrete_logarithm

## Supported Groups

Currently, we support the following Elliptic-Curve Groups:
1. [`ristretto`], used by default;
2. [`p256`], enabled by features;
3. [`k256`], enabled by features; 
4. [`p384`], enabled by features.

[`ristretto`] is build on top of the fast performing `Curve25519` and follows Mike Hamburg’s [`Decaf`] construction. While many cryptographic systems require a group of prime order, most concrete elliptic-curve implementations fall short: they either offer a group of prime order with incomplete or variable-time addition formulas (e.g., many Weierstrass models), or they provide a fast and secure group whose order is not strictly prime but instead of the form $hq$, where $h$ is a small cofactor (e.g., `Curve25519`, which has a cofactor of 8).

Curve cofactors have been the cause of [several vulnerabilities](https://ristretto.group/why_ristretto.html#pitfalls-of-a-cofactor), however, when properly handled, they can allow for much better performance. 

[`ristretto`] addresses these issues by providing a prime-order group abstraction over `Curve25519`.

[`p256`] and [`p384`] curves have long been officially recommended by the National Institute of Standards and Technology (NIST). Additionally, since 2023, `Curve25519` is also included in the list of approved curves; see [SP 800-186](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf).

[`ristretto`]: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html
[`p256`]: https://docs.rs/p256/latest/p256/
[`k256`]: https://docs.rs/k256/latest/k256/
[`p384`]: https://docs.rs/p384/latest/p384/
[`Decaf`]: https://eprint.iacr.org/2015/673.pdf