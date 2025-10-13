# Contributing

Contributions are welcome! Please follow these guidelines to help us keep development consistent.

## Code Style
- Follow the official Rust style; code must be formatted with `rustfmt`.
- Keep functions small and focused; cryptographic code should remain **constant-time** where appropriate.
- Public APIs should include documentation comments with examples.

## Tests & Benchmarks
- Add unit tests for new features or bug fixes.
- Place benchmarks under `benches/` (see `benches/group_bench.rs` for examples).
- Ensure all tests pass before opening a pull request.

## Documentation
- Update the relevant section in the [mdBook docs](./docs) when introducing new features.
- Include references to the original papers/protocols if the implementation is research-based.

## Pull Requests
- Clearly describe the goal of the PR and the motivation behind it.
- Reference any related issues if applicable.

Before submitting a PR, please make sure that all checks pass locally. The CI runs on the latest stable Rust and includes:

- **Formatting** using `cargo fmt --all`
- **Linting** using `cargo clippy`
- **Dependency auditing** using `cargo deny`
- **Tests** using `cargo test`

A complete list of checks can be found in the [CI workflow file](.github/workflows/ci.yml).

## Development Setup
To set up your environment locally install [Rust](https://www.rust-lang.org/) (latest stable) and required components:
```bash
rustup component add rustfmt clippy
```
Install [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) for dependency auditing:
```bash
cargo install --locked cargo-deny
