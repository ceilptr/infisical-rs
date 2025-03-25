use std::net::IpAddr;

use secrecy::{SecretBox, SecretString};
use serde::{Deserialize, Serialize};

// used as Universal Auth login credentials for Infisical
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

    use crate::infisical::utils::api_utils::AppConfig;

    pub fn construct_universal_auth_token_endpoint_url(
        app_config: &AppConfig,
        version: &str,
        endpoint_action: &str,
    ) {
        let endpoint_url = format!(
            "{host_url}/api/{version}/auth/token/{token_endpoint_action}",
            host_url = app_config.host,
            version = &version,
            token_endpoint_action = endpoint_action
        );
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
