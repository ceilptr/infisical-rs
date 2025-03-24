use std::fmt::Display;

use serde::{Deserialize, Serialize};

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct OkApiResponse {
//     pub req_id: String,
//     pub status_code: i32,
//     pub message: String,
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]

// pub struct BadApiResponse {
//     pub req_id: String,
//     pub status_code: i32,
//     pub message: String,
//     pub error: String,
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct UnauthorizedApiResponse {
//     pub req_id: String,
//     pub status_code: i32,
//     pub message: String,
//     pub error: String,
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct ForbiddenApiResponse {
//     pub req_id: String,
//     pub status_code: i32,
//     pub details: String,
//     pub message: String,
//     pub error: String,
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct NotFoundApiResponse {
//     pub req_id: String,
//     pub status_code: i32,
//     pub message: String,
//     pub error: String,
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct UnprocessableContentApiResponse {
//     pub req_id: String,
//     pub status_code: i32,
//     pub message: String,
//     pub error: String,
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct InternalServerErrorApiResponse {
//     pub req_id: String,
//     pub status_code: i32,
//     pub message: String,
//     pub error: String,
// }
// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct EmptyApiResponse {}
// #[derive(Display)]
// pub trait ApiResponseTrait {
//     fn display(&self) -> String;
// }

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]

pub enum ApiResponseEnum {
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

impl Display for ApiResponseEnum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiResponseEnum::Ok => todo!(),
            ApiResponseEnum::BadRequest {
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
            ApiResponseEnum::Unauthorized {
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
            ApiResponseEnum::Forbidden {
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
            ApiResponseEnum::NotFound {
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
            ApiResponseEnum::UnprocessableContent {
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
            ApiResponseEnum::InternalServerError {
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
