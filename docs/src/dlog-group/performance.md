# Performance
---

We report the timings of the main operations for each supported curve, where $P, Q \in \mathbb{G}$ and $a, b \in \mathbb{Z}_n$. Note that performance is not the only metric to consider when choosing a curve, for example, P384 offers a higher security level (in bits) compared to the others. The data below was collected on an Intel® Core™ Ultra 7 165H and is represented in nanoseconds (ns).


| Operation       | Ristretto | K256     | P256     | P384      |
|-----------------|-----------|----------|----------|-----------|
| $[r]P$          | 24,168    | 29,407   | 90,251   | 379,02    |
| $P + Q$         | 139.93    | 172.77   | 265.80   | 762.73    |
| $a + b$         | 17.263    | 8.7378   | 8.8894   | 14.125    |
| $a \cdot b$     | 60.127    | 24.545   | 45.440   | 46.204    |