use crate::infisical::utils::api_utils::ApiResponse;

// ---------------------------------------------------------------------------------------------------------
pub trait UniversalAuthErrorTrait {}

#[derive(thiserror::Error, Debug)]
pub enum UniversalAuthError {
    #[error(
        "
        API Error: {response_status:?}: {response_error_message:?} \n\
        Details: {response_error_details:?} \n\
        This could mean a few things: \n\
            - the client id, client secret, identity id, or version specified was incorrect, \n\
            - the actual Universal Auth client secret's maximum use limit has been exceeded \n"
    )]
    GetHTMLResponseError {
        response_status: String,
        response_error_message: String,
        response_error_details: String,
    },

    // note: the Either() is because depending on where exactly we catch an error in login
    #[error(
        "Could not retrieve an access token with the given credentials: \n\
        Client ID: {client_id} \n\
        Client Secret: ************** \n\
        Client identity ID: {client_identity_id} \n\
        Universal Auth API Version: {api_version} \n\n\
        {error:#?}. \n\n \
            This could mean a few things: \n\
                -   the client id, client secret, identity id, or version specified was incorrect, \n\
                -   the actual Universal Auth client secret's maximum use limit has been exceeded, \n\
                -   or the configuration for this Universal Auth identity does not allow logging in \
                    for whatever reason, and the organization needs to be contacted. \n"
    )]
    UniversalAuthLoginError {
        // credentials: UniversalAuthCredentials,
        client_id: String,
        client_identity_id: String,
        api_version: String,
        error: ApiResponse,
    },

    #[error("No Universal Auth API Client ID Credentials Specified ")]
    NoUniversalAuthAPIClientIDSpecified,

    #[error("No Universal Auth API Client Secret Credentials Specified ")]
    NoUniversalAuthAPIClientSecretsSpecified,

    #[error("No Universal Auth API Identity ID Credentials Specified ")]
    NoUniversalAuthApiIdentityIDSpecified,

    #[error("Invalid Universal Auth API Version Credentials Specified: {version} ")]
    NoUniversalAuthAPIVersionSpecified { version: String },

    #[error(
        "
    Could not retrieve the given identity {identity}. Most likely the identity does not exist, \
    or the API version {api_version} being used is causing issues. \n\
    Error: {error:#?} \n
    "
    )]
    RetrieveIdentityError {
        identity: String,
        api_version: String,
        error: ApiResponse,
    },

    #[error("UniversalAuth::update(): {error:#?}")]
    UpdateIdentityError { error: reqwest::Error },

    #[error("UniversalAuth::revoke: {error:#?}")]
    RevokeClientSecretError { error: reqwest::Error },

    #[error("UniversalAuth::create_client_secret: {error:#?}")]
    CreateClientSecretError { error: serde_json::Error },

    #[error("UniversalAuth::list_client_secrets: {error:#?}")]
    ListClientSecretsError { error: serde_json::Error },

    #[error(
        "UniversalAuth::attach(): 
        Identity ID: {client_identity_id}
        API Version: {version}
        Err: {error:#?}"
    )]
    AttachConfigurationError {
        // err_text: String,
        // error: serde_json::Error,
        client_identity_id: String,
        version: String,
        error: ApiResponse,
    },

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("{error:#?}")]
    StdError { error: String },
    #[error(transparent)]
    Other { error: anyhow::Error },
}

impl UniversalAuthErrorTrait for UniversalAuthError {}
