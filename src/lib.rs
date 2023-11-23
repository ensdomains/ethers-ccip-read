//! # Ethers CCIP-Read
//!
//! Provides an [ethers](https://docs.rs/ethers) compatible middleware for submitting
pub use errors::CCIPReadMiddlewareError;
use ethers_core::types::{Address, Bytes};
pub use middleware::CCIPReadMiddleware;

mod ccip;
mod errors;
mod middleware;
pub mod utils;

#[derive(Debug, Clone)]
pub struct CCIPRequest {
    pub url: String,
    pub sender: Address,
    pub calldata: Bytes,
}
