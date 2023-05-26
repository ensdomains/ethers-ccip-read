use std::str::FromStr;

use async_recursion::async_recursion;
use async_trait::async_trait;

use ethers_core::{
    abi::{self, Detokenize, ParamType, Token},
    types::{
        transaction::eip2718::TypedTransaction, Address, BlockId, BlockNumber, Bytes,
        NameOrAddress, Selector, TransactionRequest, H160, U256,
    },
    utils::{self, hex},
};
use ethers_providers::{ens, erc, Middleware, MiddlewareError};
use futures_util::try_join;
use hex::FromHex;
use reqwest::{Response, Url};
use serde_json::Value;

use crate::{
    utils::{decode_bytes, dns_encode},
    CCIPReadMiddlewareError,
};

#[derive(Debug)]
pub struct CCIPReadMiddleware<M> {
    inner: M,
    ens: Option<Address>,
}

static MAX_CCIP_REDIRECT_ATTEMPT: u8 = 10;

impl<M> CCIPReadMiddleware<M>
where
    M: Middleware,
{
    /// Creates an instance of CCIPReadMiddleware
    /// `ìnner` the inner Middleware
    pub fn new(inner: M) -> Self {
        Self { inner, ens: None }
    }

    /// Sets the ENS Address (default: mainnet)
    #[must_use]
    pub fn ens<T: Into<Address>>(mut self, ens: T) -> Self {
        self.ens = Some(ens.into());
        self
    }

    /// The supports_wildcard checks if a given resolver supports the wildcard resolution by calling
    /// its `supportsInterface` function with the `resolve(bytes,bytes)` selector.
    ///
    /// # Arguments
    ///
    /// * `resolver_address`: The resolver's address.
    ///
    /// # Returns
    ///
    /// A `Result` with either a `bool` value indicating if the resolver supports wildcard
    /// resolution or a `ProviderError`.
    pub async fn supports_wildcard(
        &self,
        resolver_address: H160,
    ) -> Result<bool, CCIPReadMiddlewareError<M>> {
        // Prepare the data for the `supportsInterface` call, providing the selector for
        // the "resolve(bytes,bytes)" function
        let data = Some(
            "0x01ffc9a79061b92300000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );

        let _tx_request = TransactionRequest {
            data,
            to: Some(NameOrAddress::Address(resolver_address)),
            ..Default::default()
        };

        let _tx_result: Result<Bytes, _> = self.call(&_tx_request.into(), None).await;
        let _tx = match _tx_result {
            Ok(_tx) => _tx,
            Err(_error) => {
                println!("Error calling: {:?}", _error);
                Bytes::from([])
            }
        };

        // If the response is empty, the resolver does not support wildcard resolution
        if _tx.0.is_empty() {
            return Ok(false);
        }

        let _result: U256 = decode_bytes(ParamType::Uint(256), _tx);

        // If the result is one, the resolver supports wildcard resolution; otherwise, it does not
        Ok(_result.eq(&U256::one()))
    }

    async fn query_resolver<T: Detokenize>(
        &self,
        param: ParamType,
        ens_name: &str,
        selector: Selector,
    ) -> Result<T, CCIPReadMiddlewareError<M>> {
        self.query_resolver_parameters(param, ens_name, selector, None)
            .await
    }

    async fn query_resolver_parameters<T: Detokenize>(
        &self,
        param: ParamType,
        ens_name: &str,
        selector: Selector,
        parameters: Option<&[u8]>,
    ) -> Result<T, CCIPReadMiddlewareError<M>> {
        let resolver_address = self.get_resolver(ens_name).await?;

        let mut tx: TypedTransaction =
            ens::resolve(resolver_address, selector, ens_name, parameters).into();

        let mut parse_bytes = false;
        if self.supports_wildcard(resolver_address).await? {
            parse_bytes = true;

            let dns_encode_token = Token::Bytes(dns_encode(ens_name).unwrap());
            let tx_data_token = Token::Bytes(tx.data().unwrap().to_vec());

            let tokens = vec![dns_encode_token, tx_data_token];

            let encoded_data = abi::encode(&tokens);

            let resolve_selector = "9061b923";

            // selector("resolve(bytes,bytes)")
            tx.set_data(Bytes::from(
                [hex::decode(resolve_selector).unwrap(), encoded_data].concat(),
            ));
        }

        // resolve
        let mut data = self.call(&tx, None).await?;
        if parse_bytes {
            data = decode_bytes(ParamType::Bytes, data);
        }

        Ok(decode_bytes(param, data))
    }

    pub async fn get_resolver(&self, ens_name: &str) -> Result<H160, CCIPReadMiddlewareError<M>> {
        let mut current_name: String = ens_name.to_string();

        let ens_addr = self.ens.unwrap_or(ens::ENS_ADDRESS);

        loop {
            if current_name.eq("") || current_name.eq(".") {
                return Ok(H160::zero());
            }

            if !ens_name.eq("eth") && current_name.eq("eth") {
                return Ok(H160::zero());
            }

            let data = self
                .call(
                    &ens::get_resolver(ens_addr, &current_name.to_string()).into(),
                    None,
                )
                .await?;

            if data.0.is_empty() {
                return Ok(H160::zero());
            }

            let resolver_address: Address = decode_bytes(ParamType::Address, data);

            if resolver_address != Address::zero() {
                if current_name != ens_name && !self.supports_wildcard(resolver_address).await? {
                    return Ok(H160::zero());
                }
                return Ok(resolver_address);
            }

            let mut splitted_name: Vec<&str> = current_name.split('.').collect();
            current_name = splitted_name.split_off(1).join(".").to_string();
        }
    }

    /// This function makes a Cross-Chain Interoperability Protocol (CCIP-Read) request
    /// and returns the result as `Bytes` or an error message.
    ///
    /// # Arguments
    ///
    /// * `sender`: The sender's address.
    /// * `tx`: The typed transaction.
    /// * `calldata`: The function call data as bytes.
    /// * `urls`: A vector of Offchain Gateway URLs to send the request to.
    ///
    /// # Returns
    ///
    /// an opaque byte string to send to callbackFunction on Offchain Resolver contract.
    async fn ccip_request(
        &self,
        sender: Address,
        tx: &TypedTransaction,
        calldata: &[u8],
        urls: Vec<&str>,
    ) -> Result<Bytes, CCIPReadMiddlewareError<M>> {
        // If there are no URLs or the transaction's destination is empty, return an empty result
        if urls.is_empty() || tx.to().is_none() {
            return Ok(Bytes::from([]));
        }

        // Convert calldata to a hex string
        let data: String = calldata
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();

        let mut error_messages: Vec<String> = vec![];

        for (_i, url) in urls.iter().enumerate() {
            // Replace the placeholders in the URL with the sender address and data
            let href = url
                .replace("{sender}", &format!("0x{:x}", sender))
                .replace("{data}", &format!("0x{}", &data.to_lowercase()).to_string());

            let mut request: reqwest::RequestBuilder = reqwest::Client::new().get(&href);

            // If the URL does not contain the "{data}" placeholder, create a POST request instead
            if !url.contains("{data}") {
                let body = serde_json::json!({ "data": data, "sender": sender });
                request = reqwest::Client::new().post(&href).json(&body);
            }

            let resp: Response = request.send().await.unwrap();

            let result: Value = resp.json().await.unwrap();
            let mut error_message = "unknown error";

            // If the result contains the "data" field, decode the data and return it as Bytes
            if let Some(returned_data) = result.get("data") {
                let decoded: Vec<u8> =
                    hex::decode(&returned_data.as_str().unwrap().to_string()[2..]).unwrap();
                return Ok(Bytes::from(decoded));
            };

            if let Some(_message) = result.get("message") {
                error_message = result["message"].as_str().unwrap();
            }

            error_messages.push(error_message.to_string());
        }

        Err(CCIPReadMiddlewareError::FetchError(
            error_messages.join(", "),
        ))
    }

    #[async_recursion]
    async fn _call(
        &self,
        transaction: &TypedTransaction,
        block_id: Option<BlockId>,
        attempt: u8,
    ) -> Result<Bytes, CCIPReadMiddlewareError<M>> {
        if attempt >= MAX_CCIP_REDIRECT_ATTEMPT {
            // may need more info
            return Err(CCIPReadMiddlewareError::MaxRedirectionError);
        }

        let tx_sender = match transaction.to().unwrap() {
            NameOrAddress::Name(ens_name) => self.resolve_name(ens_name).await?,
            NameOrAddress::Address(addr) => *addr,
        };

        // let tx_value: Value = utils::serialize(transaction);
        let block_value = utils::serialize(&block_id.unwrap_or_else(|| BlockNumber::Latest.into()));
        let result = match self.inner().call(transaction, block_id).await {
            Ok(response) => response.to_string(),
            Err(provider_error) => {
                let content = provider_error.as_error_response().unwrap();
                let data = content.data.as_ref().unwrap_or(&serde_json::Value::Null);
                if data.is_null() {
                    return Err(CCIPReadMiddlewareError::GatewayError(content.to_string()));
                }
                data.to_string()
                    .trim_matches('"')
                    .trim_start_matches("0x")
                    .to_string()
            }
        };

        if block_value.eq("latest")
            && !tx_sender.is_zero()
            && result.starts_with("556f1830")
            && hex::decode(result.clone()).unwrap().len() % 32 == 4
        {
            let output_types = vec![
                ParamType::Address,                            // 'address'
                ParamType::Array(Box::new(ParamType::String)), // 'string[]'
                ParamType::Bytes,                              // 'bytes'
                ParamType::FixedBytes(4),                      // 'bytes4'
                ParamType::Bytes,                              // 'bytes'
            ];

            let decoded_data: Vec<abi::Token> =
                abi::decode(&output_types, &Vec::from_hex(&result.clone()[8..]).unwrap()).unwrap();

            if let (
                Token::Address(addr),
                Token::Array(strings),
                Token::Bytes(bytes),
                Token::FixedBytes(bytes4),
                Token::Bytes(bytes2),
            ) = (
                decoded_data.get(0).unwrap(),
                decoded_data.get(1).unwrap(),
                decoded_data.get(2).unwrap(),
                decoded_data.get(3).unwrap(),
                decoded_data.get(4).unwrap(),
            ) {
                let sender: Address = *addr;
                let urls: Vec<&str> = strings
                    .iter()
                    .map(|t| match t {
                        Token::String(s) => s.as_str(),
                        _ => panic!("CCIP Read contained corrupt URL string"),
                    })
                    .collect();

                let call_data: &[u8] = bytes;
                let callback_selector: Vec<u8> = bytes4.clone();
                let extra_data: &[u8] = bytes2;

                if !sender.eq(&tx_sender) {
                    return Err(CCIPReadMiddlewareError::SenderError {
                        sender: format!("0x{:x}", sender),
                    });
                }

                let ccip_result = self
                    .ccip_request(sender, transaction, call_data, urls)
                    .await?;
                if ccip_result.is_empty() {
                    return Err(CCIPReadMiddlewareError::GatewayNotFoundError);
                }

                let ccip_result_token = Token::Bytes(ccip_result.as_ref().to_vec());
                let extra_data_token = Token::Bytes(extra_data.into());

                let tokens = vec![ccip_result_token, extra_data_token];

                let encoded_data = abi::encode(&tokens);
                let mut new_transaction = transaction.clone();
                new_transaction.set_data(Bytes::from(
                    [callback_selector.clone(), encoded_data.clone()].concat(),
                ));

                return self._call(&new_transaction, block_id, attempt + 1).await;
            }
        }
        let result = match Bytes::from_str(&result) {
            Ok(bytes) => bytes,
            Err(error) => {
                println!("error: {:?}", error);
                return Err(CCIPReadMiddlewareError::GatewayError(error.to_string()));
            }
        };

        Ok(result)
    }
}

/// Middleware implementation for CCIPReadMiddleware
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<M> Middleware for CCIPReadMiddleware<M>
where
    M: Middleware,
{
    type Error = CCIPReadMiddlewareError<M>;
    type Provider = M::Provider;
    type Inner = M;

    /// Get a reference to the inner middleware
    fn inner(&self) -> &M {
        &self.inner
    }

    /// Call the underlying middleware with the provided transaction and block
    async fn call(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<Bytes, Self::Error> {
        return self._call(tx, block, 0).await;
    }

    /// Resolve a field of an ENS name
    async fn resolve_field(&self, ens_name: &str, field: &str) -> Result<String, Self::Error> {
        let field: String = self
            .query_resolver_parameters(
                ParamType::String,
                ens_name,
                ens::FIELD_SELECTOR,
                Some(&ens::parameterhash(field)),
            )
            .await?;
        Ok(field)
    }

    /// Resolve avatar field of an ENS name
    async fn resolve_avatar(&self, ens_name: &str) -> Result<Url, Self::Error> {
        let (field, owner) = try_join!(
            self.resolve_field(ens_name, "avatar"),
            self.resolve_name(ens_name)
        )?;
        let url = Url::from_str(&field)
            .map_err(|e| CCIPReadMiddlewareError::URLParseError(e.to_string()))?;
        match url.scheme() {
            "https" | "data" => Ok(url),
            "ipfs" => erc::http_link_ipfs(url).map_err(CCIPReadMiddlewareError::URLParseError),
            "eip155" => {
                let token = erc::ERCNFT::from_str(url.path())
                    .map_err(CCIPReadMiddlewareError::URLParseError)?;
                match token.type_ {
                    erc::ERCNFTType::ERC721 => {
                        let tx = TransactionRequest {
                            data: Some(
                                [&erc::ERC721_OWNER_SELECTOR[..], &token.id].concat().into(),
                            ),
                            to: Some(NameOrAddress::Address(token.contract)),
                            ..Default::default()
                        };
                        let data = self.call(&tx.into(), None).await?;
                        if decode_bytes::<Address>(ParamType::Address, data) != owner {
                            return Err(CCIPReadMiddlewareError::NFTOwnerError(
                                "Incorrect owner.".to_string(),
                            ));
                        }
                    }
                    erc::ERCNFTType::ERC1155 => {
                        let tx = TransactionRequest {
                            data: Some(
                                [
                                    &erc::ERC1155_BALANCE_SELECTOR[..],
                                    &[0x0; 12],
                                    &owner.0,
                                    &token.id,
                                ]
                                .concat()
                                .into(),
                            ),
                            to: Some(NameOrAddress::Address(token.contract)),
                            ..Default::default()
                        };
                        let data = self.call(&tx.into(), None).await?;
                        if decode_bytes::<u64>(ParamType::Uint(64), data) == 0 {
                            return Err(CCIPReadMiddlewareError::NFTOwnerError(
                                "Incorrect balance.".to_string(),
                            ));
                        }
                    }
                }

                let image_url = self.resolve_nft(token).await?;
                match image_url.scheme() {
                    "https" | "data" => Ok(image_url),
                    "ipfs" => erc::http_link_ipfs(image_url)
                        .map_err(CCIPReadMiddlewareError::URLParseError),
                    _ => Err(CCIPReadMiddlewareError::UnsupportedURLSchemeError),
                }
            }
            _ => Err(CCIPReadMiddlewareError::UnsupportedURLSchemeError),
        }
    }

    /// Resolve an ENS name to an address
    async fn resolve_name(&self, ens_name: &str) -> Result<Address, Self::Error> {
        self.query_resolver(ParamType::Address, ens_name, ens::ADDR_SELECTOR)
            .await
    }

    /// Look up an address to find its primary ENS name
    async fn lookup_address(&self, address: Address) -> Result<String, Self::Error> {
        let ens_name = ens::reverse_address(address);
        let domain: String = self
            .query_resolver(ParamType::String, &ens_name, ens::NAME_SELECTOR)
            .await?;
        let reverse_address = self.resolve_name(&domain).await?;
        if address != reverse_address {
            Err(CCIPReadMiddlewareError::EnsNotOwned(domain))
        } else {
            Ok(domain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers_core::types::TransactionRequest;
    use ethers_providers::MAINNET;

    #[tokio::test]
    async fn test_eip_2544_ens_wildcards() {
        let provider = CCIPReadMiddleware::new(MAINNET.provider());

        let ens_name = "1.offchainexample.eth";
        let resolver_address = provider.get_resolver(ens_name).await.unwrap();
        assert_eq!(
        resolver_address,
        Address::from_str("0xC1735677a60884ABbCF72295E88d47764BeDa282").unwrap(),
        "Expected resolver_address to be 0xC1735677a60884ABbCF72295E88d47764BeDa282, but got {}",
        resolver_address
    );

        let supports_wildcard = provider.supports_wildcard(resolver_address).await.unwrap();
        assert_eq!(
            supports_wildcard, true,
            "Wildcard is not supported, expected to be true"
        );

        let resolved_address = provider.resolve_name(ens_name).await.unwrap();
        assert_eq!(
        resolved_address,
        Address::from_str("0x41563129cDbbD0c5D3e1c86cf9563926b243834d").unwrap(),
        "Expected resolved_address to be 0x41563129cDbbD0c5D3e1c86cf9563926b243834d, but got {}",
        resolved_address
    );
    }

    #[tokio::test]
    async fn test_ccip_call() {
        let resolver_address = "0xC1735677a60884ABbCF72295E88d47764BeDa282";
        let email = "nick@ens.domains";

        let provider = CCIPReadMiddleware::new(MAINNET.provider());

        let tx = TransactionRequest {
        // parameters = text(bytes32 node, string calldata key) node: namehash('1.offchainexample.eth'), key: 'email'
        // tx_data = selector(resolve(bytes,bytes)), namehash(name), parameters
        // ensip10 interface + encode(dnsencode(name), tx_data)
        data: Some(Bytes::from(hex::decode("9061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap())),
        to: Some(resolver_address.into()),
        ..Default::default()
    }.into();

        let result = provider.call(&tx, None).await.unwrap();

        let data: Bytes = decode_bytes(ParamType::Bytes, result);
        let record: String = decode_bytes(ParamType::String, data);

        assert_eq!(record, email);
    }

    // todo: requires modification in ethers-rs, uncomment when merged
    //
    // #[tokio::test]
    // async fn test_mismatched_sender() {
    //     let resolver_address = "0xC1735677a60884ABbCF72295E88d47764BeDa282";

    //     let (provider, mock) = Provider::mocked();
    //     let provider = CCIPReadMiddleware::new(provider);

    //     let tx: TypedTransaction = TransactionRequest {
    //     // parameters = text(bytes32 node, string calldata key) node: namehash('1.offchainexample.eth'), key: 'email'
    //     // tx_data = selector(resolve(bytes,bytes)), namehash(name), parameters
    //     // ensip10 interface + encode(dnsencode(name), tx_data)
    //     data: Some(Bytes::from(hex::decode("9061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap())),
    //     to: Some(resolver_address.into()),
    //     ..Default::default()
    // }.into();

    //     let error_code = 3;
    //     // sender information altered to c1735677a60884abbcf72295e88d47764beda283
    //     let error_data = r#""0x556f1830000000000000000000000000c1735677a60884abbcf72295e88d47764beda28300000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000160f4d4d2f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004768747470733a2f2f6f6666636861696e2d7265736f6c7665722d6578616d706c652e75632e722e61707073706f742e636f6d2f7b73656e6465727d2f7b646174617d2e6a736f6e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001449061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001449061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000""#;
    //     let error_message = "execution reverted";
    //     let error = JsonRpcError {
    //         code: error_code,
    //         data: Some(serde_json::from_str(error_data).unwrap()),
    //         message: error_message.to_string(),
    //     };
    //     mock.push_response(MockResponse::Error(error.clone()));

    //     let result = provider.call(&tx, None).await;
    //     assert!(result.is_err());
    //     assert_eq!(
    //         result.unwrap_err().to_string(),
    //         format!(
    //             "CCIP Read sender did not match {}",
    //             "0xc1735677a60884abbcf72295e88d47764beda283"
    //         )
    //     );
    // }
}
