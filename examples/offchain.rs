use anyhow::Result;
use ethers::prelude::*;
use ethers_ccip_read::CCIPReadMiddleware;
use std::convert::TryFrom;

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to the network
    let provider = Provider::<Http>::try_from("https://your.web3.provider")?;

    // Add ccip-read middleware
    let provider = CCIPReadMiddleware::new(provider);

    let ens_name = "1.offchainexample.eth";
    let resolver_address = provider.get_resolver(ens_name).await.unwrap();
    println!("resolver_address: {:?}", resolver_address);

    let supports_wildcard = provider.supports_wildcard(resolver_address).await.unwrap();
    println!("supports_wildcard: {:?}", supports_wildcard);

    let resolved_address = provider.resolve_name(ens_name).await.unwrap();
    println!("resolved_address: {:?}", resolved_address);
    Ok(())
}
