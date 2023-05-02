//! # Ethers CCIP-Read
//!
//! Provides an [ethers](https://docs.rs/ethers) compatible middleware for submitting
mod middleware;
pub use middleware::CCIPReadMiddleware;

mod errors;
pub use errors::CCIPReadMiddlewareError;

pub mod utils;
