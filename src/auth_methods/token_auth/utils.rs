use serde::{Deserialize, Serialize};

use crate::utils::api_utils::{AccessTokenTrustedIp, ClientSecretTrustedIp};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct IdentityTokenAuth {
    pub id: String,
    #[serde(rename(serialize = "access_token_ttl", deserialize = "accessTokenTTL"))]
    pub access_token_ttl: u128,
    #[serde(rename(serialize = "access_token_max_ttl", deserialize = "accessTokenMaxTTL"))]
    pub access_token_max_ttl: u128,
    pub access_token_num_uses_limit: u128,
    pub access_token_trusted_ips: Vec<AccessTokenTrustedIp>,
    pub client_secret_trusted_ips: Vec<ClientSecretTrustedIp>,
    pub created_at: String,
    pub updated_at: String,
    pub identity_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct TokenAuthAccessToken {
    pub access_token: String,
    pub expires_in: u128,
    #[serde(rename(serialize = "access_token_max_ttl", deserialize = "accessTokenMaxTTL"))]
    pub access_token_max_ttl: u128,
    token_type: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct Token {
    pub id: String,
    #[serde(rename(serialize = "access_token_ttl", deserialize = "accessTokenTTL"))]
    pub access_token_ttl: u128,
    #[serde(rename(serialize = "access_token_max_ttl", deserialize = "accessTokenMaxTTL"))]
    pub access_token_max_ttl: u128,
    pub access_token_num_uses: u128,
    pub access_token_num_uses_limit: u128,
    pub access_token_last_used_at: String,
    pub access_token_last_reused_at: String,
    pub is_access_token_revoked: bool,
    #[serde(rename(
        serialize = "identity_ua_client_secret_id",
        deserialize = "identityUAClientSecretId"
    ))]
    pub identity_ua_client_secret_id: String,
    pub identity_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub name: String,
    pub auth_method: String,
}

pub struct RevokedToken {
    pub message: String,
}
