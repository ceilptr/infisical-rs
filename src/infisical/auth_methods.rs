pub mod aws_auth;
pub mod azure_auth;
pub mod gcp_auth;
pub mod jwt_auth;
pub mod kubernetes_auth;
pub mod oidc_auth;
pub mod token_auth;

#[doc = include_str!("auth_methods/universal_auth/documentation/module.md")]
pub mod universal_auth;
