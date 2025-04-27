use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::auth_methods::universal_auth::utils::{
    UniversalAuthCredentials,
    universal_auth_util_functions::{
        default_access_token_trusted_ip_form_data_vectors,
        default_client_secret_trusted_ip_form_data_vectors,
    },
};

pub struct AppConfig {
    pub host: String,
    pub client: reqwest::Client,
    // pub client: reqwest::blocking::Client,
}

// note: the strum to_string macros are mostly for api path construction
// to clean up some patern matching stuff down the line (moreso because 'm lazy, to be blunt)
#[derive(strum::Display, PartialEq)]
// #[derive(Display, Debug, PartialEq)]
pub enum AuthMethod {
    #[strum(to_string = "universal-auth")]
    Universal {
        credentials: UniversalAuthCredentials,
    },
    #[strum(to_string = "token")]
    Token { token: String, identity_id: String },
}

// ---------------------------------------------------------
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct ClientSecretTrustedIp {
    pub ip_address: String,
    pub prefix: u128,
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct AccessTokenTrustedIp {
    pub ip_address: String,
    pub prefix: u128,
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: String,
}

pub fn construct_trusted_ip_form_data(
    client_secret_trusted_ips: Option<&Vec<(String, IpAddr)>>,
    access_token_trusted_ips: Option<&Vec<(String, IpAddr)>>,
) {
    let mut trusted_ips_config_form_data = HashMap::new();

    // set up client secret and access tokens trusted IPs in request form
    // im fairly sure this is an Infisical Pro-only feature, and will default to 0.0.0.0 and ::0 for both fields and ignore user inputs
    // regardless of user input on free plans
    if client_secret_trusted_ips.is_none() {
        // check for user client secret trusted IPs
        trusted_ips_config_form_data.insert(
            "clientSecretTrustedIpsStruct",
            default_client_secret_trusted_ip_form_data_vectors(),
        );
    } else if access_token_trusted_ips.is_none() {
        trusted_ips_config_form_data.insert(
            "accessTokenTrustedIpsStruct",
            default_access_token_trusted_ip_form_data_vectors(),
        );
    } else {
        //insert both user-defined client secret and access token trusted IPs
        trusted_ips_config_form_data.insert(
            "clientSecretTrustedIpsStruct",
            client_secret_trusted_ips.unwrap().clone(),
        );

        trusted_ips_config_form_data.insert(
            "accessTokenTrustedIpsStruct",
            access_token_trusted_ips.unwrap().clone(),
        );
    }
}
// ---------------------------------------------------------

// ---------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum ApiResponse {
    #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
    Ok,
    #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
    BadRequest {
        req_id: String,
        status_code: u16,
        message: String,
        error: String,
    },
    #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
    Unauthorized {
        req_id: String,
        status_code: u16,
        message: String,
        error: String,
    },
    #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
    Forbidden {
        req_id: String,
        status_code: u16,
        details: String,
        message: String,
        error: String,
    },
    #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
    NotFound {
        // req_id: String,
        error: String,
        message: String,
        status_code: u16,
    },
    #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
    UnprocessableContent {
        req_id: String,
        status_code: u16,
        message: String,
        error: String,
    },
    #[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
    InternalServerError {
        req_id: String,
        status_code: u16,
        message: String,
        error: String,
    },
}

impl std::fmt::Display for ApiResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiResponse::Ok => todo!(),
            ApiResponse::BadRequest {
                req_id,
                status_code,
                message,
                error,
            } => write!(
                f,
                "
                req_id: {req_id} \n,
                status_code: {status_code} \n,
                message: {message} \n,
                error: {error} \n,
            ",
                req_id = req_id,
                status_code = status_code,
                message = message,
                error = error,
            ),
            ApiResponse::Unauthorized {
                req_id,
                status_code,
                message,
                error,
            } => write!(
                f,
                "
                req_id: {req_id} \n,
                status_code: {status_code} \n,
                message: {message} \n,
                error: {error} \n,
            ",
                req_id = req_id,
                status_code = status_code,
                message = message,
                error = error,
            ),
            ApiResponse::Forbidden {
                req_id,
                status_code,
                details,
                message,
                error,
            } => write!(
                f,
                "
                req_id: {req_id} \n,
                status_code: {status_code} \n,
                details: {details} \n,
                message: {message} \n,
                error: {error} \n,
            ",
                req_id = req_id,
                status_code = status_code,
                details = details,
                message = message,
                error = error,
            ),
            ApiResponse::NotFound {
                // req_id,
                error,
                message,
                status_code,
            } => write!(
                f,
                "
                status_code: {status_code} \n,
                message: {message} \n,
                error: {error} \n,
            ",
                // req_id = req_id,
                error = error,
                message = message,
                status_code = status_code,
            ),
            ApiResponse::UnprocessableContent {
                req_id,
                status_code,
                message,
                error,
            } => write!(
                f,
                "
                req_id: {req_id} \n,
                status_code: {status_code} \n,
                message: {message} \n,
                error: {error} \n,
            ",
                req_id = req_id,
                status_code = status_code,
                message = message,
                error = error,
            ),
            ApiResponse::InternalServerError {
                req_id,
                status_code,
                message,
                error,
            } => write!(
                f,
                "
                req_id: {req_id} \n,
                status_code: {status_code} \n,
                message: {message} \n,
                error: {error} \n,
            ",
                req_id = req_id,
                status_code = status_code,
                message = message,
                error = error,
            ),
        }
    }
}
