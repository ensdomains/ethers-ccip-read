## Ethers-rs CCIP-Read Middleware

<!-- Badges -->
[![CI Status][ci-badge]][ci-url]
[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]

<!-- Badge Images -->
[ci-badge]: https://github.com/ensdomains/ethers-ccip-read/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/ensdomains/ethers-ccip-read/actions/workflows/ci.yml
[crates-badge]: https://img.shields.io/crates/v/ethers-ccip-read.svg

<!-- Target URLs -->
[crates-url]: https://crates.io/crates/ethers-ccip-read
[docs-badge]: https://docs.rs/ethers-ccip-read/badge.svg
[docs-url]: https://docs.rs/ethers-ccip-read

Ready to dive into the world of cross-chain data access? Look no further! This Rust library provides an Ethers middleware to extend ENS (Ethereum Name Service) functionality with [CCIP-Read](https://eips.ethereum.org/EIPS/eip-3668) (Cross-Chain Interoperability Protocol - Secure offchain data retrieval) support. Easily interact with ENS names that support the CCIP-Read protocol and make your decentralized applications more fun and powerful!

### Installation: As Easy as 1-2-3!

To install the `ethers-ccip-read` middleware, add it to your `Cargo.toml` file:

```toml
ethers-ccip-read = { git = "https://github.com/ensdomains/ethers-ccip-read" }
```

### Usage: Let the Cross-Chain Fun Begin!

Hook up the middleware to your Ethers provider and start your cross-chain adventure! Here's a simple example to get you going;

```rs
use anyhow::Result;
use ethers_ccip_read::*;
use std::convert::TryFrom;

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to the network
    let provider = Provider::<Http>::try_from("https://your.web3.provider")?;

    // Enable the middleware
    let provider = CCIPReadMiddleware::new(
        provider,
    );

    // Now you can query CCIP-Read supported ENS names.
    let ens_name = "1.offchainexample.eth";
    let resolver_address = provider.get_resolver(ens_name).await.unwrap();
    println!("resolver_address: {:?}", resolver_address);

    let supports_wildcard = provider.supports_wildcard(resolver_address).await.unwrap();
    println!("supports_wildcard: {:?}", supports_wildcard);

    let resolved_address = provider.resolve_name(ens_name).await.unwrap();
    println!("resolved_address: {:?}", resolved_address);

    Ok(())
}
```

For more examples, check out [the examples](./examples) directory.

### Helpful Resources: What more I can learn about CCIP-Read? 

- https://github.com/smartcontractkit/ccip-read
- https://github.com/ensdomains/offchain-resolver
- https://eips.ethereum.org/EIPS/eip-3668
