# Reference environment

| Component | Version or configuration |
| --- | --- |
| Computer | MacBook Pro |
| Processor | Apple M2 Pro |
| CPU cores | 10: 6 performance, 4 efficiency |
| Memory | 32 GB |
| Operating system | macOS 14.6.1 |
| Architecture | aarch64 |
| Rust compiler | 1.94.1 |
| Cargo | 1.94.1 |
| LLVM | 21.1.8 |
| Python | 3.11.4 |
| Matplotlib | 3.8.4 |
| NumPy | 2.2.6 |
| Figure font | Arial |

| Main Rust dependency | Locked version |
| --- | --- |
| blstrs | 0.7.1 |
| blst | 0.3.17, `no-threads` |
| ff | 0.13.1 |
| group | 0.13.0 |
| rand | 0.8.8 |
| sha2 | 0.10.9 |

Measurements use an optimized release build with the default feature set and single-threaded group arithmetic. Operation-count tests use the separate `op-count` feature. The compiler is pinned in `rust-toolchain.toml`; complete Rust and plotting dependencies are in `Cargo.lock` and `scripts/requirements.txt`.
