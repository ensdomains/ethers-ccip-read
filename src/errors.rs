use ethers_core::utils::hex::FromHexError;
use std::collections::HashMap;
use std::fmt::Display;

use ethers_providers::{Middleware, MiddlewareError};
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum CCIPRequestError {
    // gateway supplied error
    #[error("Gateway error: {0}")]
    GatewayError(String),

    // when gateway either fails to respond with an expected format
    #[error("Gateway format error: {0}")]
    GatewayFormatError(String),

    #[error("HTTP error: {0}")]
    HTTPError(#[from] reqwest::Error),
}

#[derive(Debug)]
pub struct CCIPFetchError(pub(crate) HashMap<String, Vec<String>>);

/// Handle CCIP-Read middlware specific errors.
#[derive(Error, Debug)]
pub enum CCIPReadMiddlewareError<M: Middleware> {
    /// Thrown when the internal middleware errors
    #[error("{0}")]
    MiddlewareError(M::Error),

    #[error("Error(s) during CCIP fetch: {0}")]
    FetchError(CCIPFetchError),

    #[error("CCIP Read sender did not match {}", sender)]
    SenderError { sender: String },

    #[error("CCIP Read no provided URLs")]
    GatewayNotFoundError,

    #[error("CCIP Read exceeded maximum redirections")]
    MaxRedirectionError,

    /// Invalid reverse ENS name
    #[error("Reversed ens name not pointing to itself: {0}")]
    EnsNotOwned(String),

    #[error("Error(s) during parsing avatar url: {0}")]
    URLParseError(String),

    #[error("Error(s) during NFT ownership verification: {0}")]
    NFTOwnerError(String),

    #[error("Error(s) decoding revert bytes: {0}")]
    HexDecodeError(#[from] FromHexError),

    #[error("Error(s) decoding abi: {0}")]
    AbiDecodeError(#[from] ethers_core::abi::Error),

    #[error("Unsupported URL scheme")]
    UnsupportedURLSchemeError,
}

impl<M: Middleware> MiddlewareError for CCIPReadMiddlewareError<M> {
    type Inner = M::Error;

    fn from_err(src: M::Error) -> Self {
        CCIPReadMiddlewareError::MiddlewareError(src)
    }

    fn as_inner(&self) -> Option<&Self::Inner> {
        match self {
            CCIPReadMiddlewareError::MiddlewareError(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for CCIPFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut errors = f.debug_struct("CCIPFetchError");

        for (url, messages) in self.0.iter() {
            errors.field(url, messages);
        }

        errors.finish()
    }
}
