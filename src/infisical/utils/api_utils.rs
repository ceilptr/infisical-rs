use serde::{Deserialize, Serialize};

use crate::infisical::auth_methods::universal_auth::utils::UniversalAuthCredentials;

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
                req_id: {req_id},
                status_code: {status_code},
                message: {message},
                error: {error},
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
                req_id: {req_id},
                status_code: {status_code},
                message: {message},
                error: {error},
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
                req_id: {req_id},
                status_code: {status_code},
                details: {details},
                message: {message},
                error: {error},
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
                status_code: {status_code},
                message: {message},
                error: {error},
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
                req_id: {req_id},
                status_code: {status_code},
                message: {message},
                error: {error},
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
                req_id: {req_id},
                status_code: {status_code},
                message: {message},
                error: {error},
            ",
                req_id = req_id,
                status_code = status_code,
                message = message,
                error = error,
            ),
        }
    }
}
