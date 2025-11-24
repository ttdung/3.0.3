## Create proof for casting a vote

## Getting Started

To start your own project, you can use our `cargo risczero` tool to write the
initial boilerplate and set up a standard directory structure.

First, [install Rust][install-rust] if you don't already have it, then install
the RISC Zero toolchain installer, `rzup`. We'll use `rzup` to install
`cargo-risczero`.

To install `rzup` run the following command and follow the instructions:

```bash
curl -L https://risczero.com/install | bash
```

Next we can install the RISC Zero toolchain by running `rzup install`:

```bash
rzup install
```

You can verify the installation was successful by running:

```bash
cargo risczero --version
```

After installation, you can create a new project (named `my_project` in this example):

```bash
cd risc0/examples/castvotes/k256

rzup install cargo-risczero 3.0.3
rzup install r0vm 3.0.3

cargo risczero --version
r0vm --version


cargo run -- /tmp/castvote/person.json --poll-id 1001 

cd ../../target/release
./k256-example -- /tmp/castvote/person.json --poll-id 1001 -
```

More details and options for `cargo risczero` are given in
[its README][cargo-risczero-readme].

For more guidance on how to use RISC Zero, how RISC Zero projects are typically
structured, and other resources useful to developers new to RISC Zero, see our
[Getting Started page][quickstart].

## Documentation

Documentation for the zkVM SDK and other Rust crates can be found at [docs.rs/risc0-zkvm](https://docs.rs/risc0-zkvm).
All other documentation can be found at [dev.risczero.com](https://dev.risczero.com).

You can build and view the Rust documentation locally by using `cargo doc`.
See [CONTRIBUTING.md](./CONTRIBUTING.md) for dependencies.
Source code for the documentation website can be found in the [website directory](./website).

## Building from source

Building from source requires some additional tools and steps.
Please refer to [CONTRIBUTING.md](./CONTRIBUTING.md) for the full instructions.

## Rust Binaries

| crate          | [crates.io]                                                                                         |
| -------------- | --------------------------------------------------------------------------------------------------- |
| cargo-risczero | [![x](https://img.shields.io/badge/crates.io-v2.1-orange)](https://crates.io/crates/cargo-risczero) |
| risc0-r0vm     | [![x](https://img.shields.io/badge/crates.io-v2.1-orange)](https://crates.io/crates/risc0-r0vm)     |
| risc0-tools    | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-tools)    |

## Rust Libraries

| crate                       | [crates.io]                                                                                                      | [docs.rs](https://docs.rs)                                                                                    |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| bonsai-sdk                  | [![x](https://img.shields.io/badge/crates.io-v1.4-orange)](https://crates.io/crates/bonsai-sdk)                  | [![](https://img.shields.io/docsrs/bonsai-sdk)](https://docs.rs/bonsai-sdk)                                   |
| risc0-binfmt                | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-binfmt)                | [![](https://img.shields.io/docsrs/risc0-binfmt)](https://docs.rs/risc0-binfmt)                               |
| risc0-build                 | [![x](https://img.shields.io/badge/crates.io-v2.1-orange)](https://crates.io/crates/risc0-build)                 | [![](https://img.shields.io/docsrs/risc0-build)](https://docs.rs/risc0-build)                                 |
| risc0-build-kernel          | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-build-kernel)          | [![](https://img.shields.io/docsrs/risc0-build-kernel)](https://docs.rs/risc0-build-kernel)                   |
| risc0-circuit-recursion     | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-circuit-recursion)     | [![](https://img.shields.io/docsrs/risc0-circuit-recursion)](https://docs.rs/risc0-circuit-recursion)         |
| risc0-circuit-recursion-sys | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-circuit-recursion-sys) | [![](https://img.shields.io/docsrs/risc0-circuit-recursion-sys)](https://docs.rs/risc0-circuit-recursion-sys) |
| risc0-circuit-rv32im        | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-circuit-rv32im)        | [![](https://img.shields.io/docsrs/risc0-circuit-rv32im)](https://docs.rs/risc0-circuit-rv32im)               |
| risc0-circuit-rv32im-sys    | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-circuit-rv32im-sys)    | [![](https://img.shields.io/docsrs/risc0-circuit-rv32im-sys)](https://docs.rs/risc0-circuit-rv32im-sys)       |
| risc0-core                  | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-core)                  | [![](https://img.shields.io/docsrs/risc0-core)](https://docs.rs/risc0-core)                                   |
| risc0-groth16               | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-groth16)               | [![](https://img.shields.io/docsrs/risc0-groth16)](https://docs.rs/risc0-groth16)                                |
| risc0-sys                   | [![x](https://img.shields.io/badge/crates.io-v1.4-orange)](https://crates.io/crates/risc0-sys)                   | [![](https://img.shields.io/docsrs/risc0-sys)](https://docs.rs/risc0-sys)                                     |
| risc0-zkp                   | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-zkp)                   | [![](https://img.shields.io/docsrs/risc0-zkp)](https://docs.rs/risc0-zkp)                                     |
| risc0-zkvm                  | [![x](https://img.shields.io/badge/crates.io-v2.1-orange)](https://crates.io/crates/risc0-zkvm)                  | [![](https://img.shields.io/docsrs/risc0-zkvm)](https://docs.rs/risc0-zkvm)                                   |
| risc0-zkvm-platform         | [![x](https://img.shields.io/badge/crates.io-v2.0-orange)](https://crates.io/crates/risc0-zkvm-platform)         | [![](https://img.shields.io/docsrs/risc0-zkvm-platform)](https://docs.rs/risc0-zkvm-platform)                 |

## Feature flags

The following feature flags are present in one or more of the crates listed above:

| Feature          | Target(s)         | Implies    | Description                                                                                                                                                  | Crates                                                               |
| ---------------- | ----------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| client           | all except rv32im | std        | Enables the client API.                                                                                                                                      | risc0-zkvm                                                           |
| cuda             |                   | prove, std | Enables CUDA GPU acceleration for the prover. Requires CUDA toolkit to be installed.                                                                         | risc0-circuit-recursion, risc0-circuit-rv32im, risc0-zkp, risc0-zkvm |
| disable-dev-mode | all except rv32im |            | Disables dev mode so that proving and verifying may not be faked. Used to prevent a misplaced `RISC0_DEV_MODE` from breaking security in production systems. | risc0-zkvm                                                           |
| metal            | macos             | prove, std | Deprecated - Metal GPU acceleration is enabled by default on Apple Silicon.                                                                                  | risc0-circuit-recursion, risc0-circuit-rv32im, risc0-zkp, risc0-zkvm |
| prove            | all except rv32im | std        | Enables the prover, incompatible within the zkvm guest.                                                                                                      | risc0-circuit-recursion, risc0-circuit-rv32im, risc0-zkp, risc0-zkvm |
| std              | all               |            | Support for the Rust stdlib.                                                                                                                                 | risc0-circuit-recursion, risc0-circuit-rv32im, risc0-zkp, risc0-zkvm |

## License

This project is licensed under the Apache2 license. See [LICENSE](LICENSE).

[actions-badge]: https://img.shields.io/github/actions/workflow/status/risc0/risc0/main.yml?branch=main
[actions-url]: https://github.com/risc0/risc0/actions?query=workflow%3ACI+branch%3Amain
[cargo-risczero-readme]: https://github.com/risc0/risc0/blob/main/risc0/cargo-risczero/README.md
[crates-badge]: https://img.shields.io/badge/crates.io-v2.0-orange
[crates-url]: https://crates.io/crates/risc0-zkvm
[crates.io]: https://crates.io
[discord-badge]: https://img.shields.io/discord/953703904086994974.svg?logo=discord&style=flat-square
[discord-url]: https://discord.gg/risczero
[install-rust]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[licence-badge]: https://img.shields.io/github/license/risc0/risc0?color=blue
[licence-url]: https://github.com/risc0/risc0/blob/main/LICENSE
[proof-system-in-detail]: https://dev.risczero.com/proof-system-in-detail.pdf
[quickstart]: https://dev.risczero.com/api/zkvm/quickstart
[risc-v]: https://en.wikipedia.org/wiki/RISC-V
[security-model]: https://dev.risczero.com/api/security-model
[twitter-badge]: https://img.shields.io/twitter/follow/risczero
[twitter-url]: https://twitter.com/risczero
[zk-proof]: https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof
[zksummit10-talk]: https://www.youtube.com/watch?v=wkIBN2CGJdc
