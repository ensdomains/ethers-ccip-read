//! # Ethers CCIP-Read
//!
//! Provides an [ethers](https://docs.rs/ethers) compatible middleware for submitting
pub use errors::CCIPReadMiddlewareError;
pub use middleware::CCIPReadMiddleware;

mod ccip;
mod errors;
mod middleware;
pub mod utils;
