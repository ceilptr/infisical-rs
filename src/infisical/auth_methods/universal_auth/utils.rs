use std::net::IpAddr;

use secrecy::{SecretBox, SecretString};
use serde::{Deserialize, Serialize};

/// This is, for all intents and purposes, your "username" and "password" for the Universal Auth authentcation method
/// in Infisical, and your entrypoint to accessing the rest of this module's functionality.
///
/// client_id: Your project identity's client id
/// client_secret: Your project identity's client secret
/// identity_id: Your project identity's id
/// version: the current Universal Auth Endpoint API version being used. Currently at v1.
///
/// # Example:
/// ```
///     let credentials = UniversalAuthCredentials {
///         client_id: ""
///         client_secret: ""
///         identity_id: ""
///         version: "v1"
///     }
/// ```
///
/// The general workflow is as follows:
/// 1) create an identity in your Infisical project with the necessary permissions
/// 2) create a client ID and client secret for said identity
/// 3)
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct UniversalAuthCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub identity_id: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct UniversalAuthAccessTokenData {
    pub access_token: String,
    #[serde(rename(serialize = "access_token_max_ttl", deserialize = "accessTokenMaxTTL"))]
    pub access_token_max_ttl: u64,
    pub expires_in: u64,
    pub token_type: String,
}

/// UniversalAuthAccessToken
///
/// The struct returned from a successful login() call. The resulting module functionality such as get_secret() or attach()
/// requires a valid access token to authenticate with Infisical. Said methods would be invoked as e.g., access_token.get_secret()
///
///
/// - data: `SecretBox<UniversalAuthAccessTokenData>`
///     - contains the actual access token data, mainly:
///         - access_token: String,
///         - access_token_max_ttl: u64,
///         - expires_in: u64,
///         - token_type: String,
/// - version:  version of the Universal Auth Endpoint API being used for this access token. Mainly carried over from the previous
///             UniversalAuthCredentials struct you'd have created previously.
///
/// Technically, any access in the secrecy-wrapped data field first needs to be "unsealed" by calling expose_secret (e.g.: user_token.data.expose_secret().access_token),
/// and this method of accessing said secrets is obviously available if need be.
/// Multiple convenience functions are available to access a given secret field, however, and are named directly after the field itself.
/// So user_token.access_token() is equivalent to calling user_token.data.expose_secret().access_token.
///
/// # Example
#[derive(Serialize, Deserialize)]
pub struct UniversalAuthAccessToken {
    // #[serde(flatten)]
    pub data: SecretBox<UniversalAuthAccessTokenData>,
    #[serde(skip)]
    pub version: String,
}

// ***********************
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct UniversalAuthClientSecretData {
    pub client_secret_num_uses: u128,
    pub client_secret_num_uses_limit: u128,
    pub client_secret_prefix: String,
    #[serde(rename(serialize = "client_secret_ttl", deserialize = "clientSecretTTL"))]
    pub client_secret_ttl: u128,
    pub created_at: String,
    pub description: String,
    pub id: String,
    #[serde(rename(serialize = "identity_ua_id", deserialize = "identityUAId"))]
    pub identity_ua_id: String,
    pub is_client_secret_revoked: bool,
    pub updated_at: String,
}

// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
// pub struct UniversalAuthClientSecretDataContainer {
//     pub clientSecretData: UniversalAuthClientSecretData,
// }

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct UniversalAuthClientSecretDataList {
    pub client_secret_data: Vec<SecretBox<UniversalAuthClientSecretData>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct UniversalAuthClientSecret {
    pub client_secret: SecretString,
    pub client_secret_data: SecretBox<UniversalAuthClientSecretData>,
}

// ---------------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct ClientSecretTrustedIpsStruct {
    pub ip_address: String,
    pub prefix: u128,
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct AccessTokenTrustedIpsStruct {
    pub ip_address: String,
    pub prefix: u128,
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
}

pub type ClientSecretTrustedIp = Vec<(String, IpAddr)>;
pub type AccessTokenTrustedIp = Vec<(String, IpAddr)>;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct IndentityUniversalAuthData {
    #[serde(rename(serialize = "access_token_max_ttl", deserialize = "accessTokenMaxTTL"))]
    pub access_token_max_ttl: u32,
    pub access_token_num_uses_limit: u32,
    #[serde(rename(serialize = "access_token_ttl", deserialize = "accessTokenTTL"))]
    pub access_token_ttl: u32,
    pub access_token_trusted_ips: Vec<AccessTokenTrustedIpsStruct>,
    pub client_id: String,
    pub client_secret_trusted_ips: Vec<ClientSecretTrustedIpsStruct>,
    pub created_at: String,
    pub id: String,
    pub identity_id: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct IndentityUniversalAuth {
    // pub identity_universal_auth: IndentityUniversalAuthData,
    pub identity_universal_auth: SecretBox<IndentityUniversalAuthData>,
}

pub mod universal_auth_util_functions {

    // im repeating myself so eventually i'll fold the endpoint url construction into a function
    // the time is now

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub fn construct_universal_auth_token_endpoint_url(
        // app_config: &AppConfig,
        host: &str,
        version: &str,
        endpoint_action: &str,
    ) -> String {
        format!(
            "{host_url}/api/{version}/auth/token/{token_endpoint_action}",
            host_url = host,
            version = &version,
            token_endpoint_action = endpoint_action
        )
    }
    // ***************************
    /**
     * These do the exact same thing, and are mainly convenience functions to clean up any identity-related functionality
     */
    pub fn default_client_secret_trusted_ip_vector() -> Vec<(String, IpAddr)> {
        vec![
            (
                "ipAddress".to_string(),
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            ),
            (
                "ipAddress".to_string(),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            ),
        ]
    }

    pub fn default_access_token_trusted_ip_vector() -> Vec<(String, IpAddr)> {
        vec![
            (
                "ipAddress".to_string(),
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            ),
            (
                "ipAddress".to_string(),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            ),
        ]
    }
}
