use either::Either;
use thiserror::Error;
// ---------------------------------------------------------------------------------------------------------
#[derive(Error, Debug)]
pub enum UniversalAuthError {
    #[error(
        "
        API Error: {response_status:?}: {reponnse_error_message:?} \n\
        Details: {reponnse_error_details:?} \n\
        This could mean a few things: \n\
            - the client id, client secret, identity id, or version specified was incorrect, \n\
            - the actual Universal Auth client secret's maximum use limit has been exceeded \n"
    )]
    GetHTMLResponseError {
        response_status: String,
        reponnse_error_message: String,
        reponnse_error_details: String,
    },
    // note: the Either() is because depending on where exactly we catch an error in login
    #[error(
        "Could not retrieve an access token with the given credentials: \n\
        Client ID: {client_id} \n\
        Client Secret: ************** \n\
        Client identity ID: {client_identity_id} \n\
        Universal Auth API Version: {version} \n\n\
        HTTP Response: {response_status} \n\
        {access_token_error}. \n\n \
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
        version: String,
        response_status: String,
        // access_token_error: reqwest::Error,
        // access_token_error: serde_json::Error,
        access_token_error: Either<serde_json::Error, String>,
    },
    #[error("No Universal Auth API Client ID Credentials Specified ")]
    NoUniversalAuthAPIClientIDSpecified,
    #[error("No Universal Auth API Client Secret Credentials Specified ")]
    NoUniversalAuthAPIClientSecretsSpecified,
    #[error("No Universal Auth API Identity ID Credentials Specified ")]
    NoUniversalAuthApiIdentityIDSpecified,
    #[error("Invalid Universal Auth API Version Credentials Specified: {version} ")]
    NoUniversalAuthAPIVersionSpecified { version: String },

    #[error("UniversalAuth::update(): {error:#?}")]
    UpdateIdentityError { error: reqwest::Error },
    #[error("UniversalAuth::revoke: {error:#?}")]
    RevokeClientSecretError { error: reqwest::Error },
    #[error("UniversalAuth::create_client_secret: {error:#?}")]
    CreateClientSecretError { error: serde_json::Error },
    #[error("UniversalAuth::list_client_secrets: {error:#?}")]
    ListClientSecretsError { error: serde_json::Error },
}
