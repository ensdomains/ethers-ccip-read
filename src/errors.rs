use ethers_providers::{Middleware, MiddlewareError};
use thiserror::Error;

/// Handle CCIP-Read middlware specific errors.
#[derive(Error, Debug)]
pub enum CCIPReadMiddlewareError<M: Middleware> {
    /// Thrown when the internal middleware errors
    #[error("{0}")]
    MiddlewareError(M::Error),

    #[error("Error(s) during CCIP fetch: {0}")]
    FetchError(String),

    #[error("CCIP Read sender did not match {}", sender)]
    SenderError { sender: String },

    #[error("Bad result from backend: {0}")]
    GatewayError(String),

    #[error("CCIP Read no provided URLs")]
    GatewayNotFoundError,

    #[error("CCIP Read exceeded maximum redirections")]
    MaxRedirectionError,

    /// Invalid reverse ENS name
    #[error("Reversed ens name not pointing to itself: {0}")]
    EnsNotOwned(String),
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
