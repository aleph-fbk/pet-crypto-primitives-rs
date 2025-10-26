# Developer Guide
---

## Group Trait

At the core of `dlog-group` is the `Group` trait, which defines the behavior expected from any prime-order group. This includes core group operations (such as addition, scalar multiplication, identity, equality), as well as serialization and size-related properties.

To extend `dlog-group` with support for a new group backend, you need to implement the following traits:

- **`GroupScalar`**: Represents scalars from the field $\mathbb{Z}_n$. You must specify their size and how to generate a random scalar using a cryptographically secure rng (i.e., one implementing [`CryptoRng`](https://rust-random.github.io/rand/rand_core/trait.CryptoRng.html)).

- **`GroupPoint`**: Represents elements of the group. This trait depends on `GroupScalar` and requires you to define the size of a point and implement scalar multiplication and point related operations.

- **`Group`**: The main trait that binds `GroupPoint` and `GroupScalar` together into a single group definition.

Once these are implemented, your group can be used interchangeably with existing ones like `RistrettoGroup`, `P256Group`, or others, benefiting from the abstraction provided by the library.

It is recommended to include proper testing within any module that introduces new functionality. Additionally, if comparing performance is of interest, you can add benchmarks in the file `benches/group_bench.rs`, at the end of the file you can find examples of how the benchmarking macros (which take advantage of the `Group` trait) are used. 

