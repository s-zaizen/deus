---
paths:
  - "crates/**/*.rs"
---
# Rust Backend

- Format: `cargo fmt`
- Lint: `cargo clippy -- -D warnings`
- Tests: `cargo test`
- Keep Rust as orchestration and integration code. ML analysis and training logic belongs in `ml/`.
- Route handlers should use shared API DTOs and the `MlClient` boundary instead of serializing ML wire formats ad hoc.
