/// Universal Authentication:
///
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    net::IpAddr,
};

use error_handling::UniversalAuthError;
use reqwest::{
    StatusCode,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use secrecy::{ExposeSecret, SecretBox, SerializableSecret, zeroize::Zeroize};

use utils::{
    universal_auth_util_functions::{
        default_access_token_trusted_ip_vector, default_client_secret_trusted_ip_vector,
    },
    *,
};

use crate::infisical::utils::{
    api_utils::ApiResponseEnum, reqwest_utils::reqwest_bytes_to_unescaped_string,
};

pub mod error_handling;
pub mod utils;

// ---------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------
/// mainly used to login With a client_id and client_secret and retrieve a Universal Auth access token to do all the things
impl UniversalAuthCredentials {
    /// login():
    /// API Reference: https://infisical.com/docs/api-reference/endpoints/universal-auth/login
    ///
    /// Takes in a client id and secret, and returns a Universal Auth Access Token upon successful authorization. \
    /// The resulting access token is then used as a mechanism for the rest of the universal auth library functionality
    /// e.g.: get_secret(), revoke_client_secret(), attach().
    ///
    /// Args:
    /// * `host` - A string slice denoting the host url used to connect to Infisical (e.g.: https://us.infisical.com, http://localhost:8080, etc)
    /// * `client` - A reqwest client used to send off the API request. Defaults to the non-blocking version unless the `reqwest_blocking` feature is enabled in compilation.
    ///
    /// Result:
    ///
    /// # Example
    ///
    /// ```
    ///     let credentials = UniversalAuthCredentials {
    ///         client_id: "",
    ///         client_secret: "",
    ///         identity_id: "",
    ///         version: "",
    ///     }
    ///
    ///     let access_token = credentials.login(host: "https://us.infisical.com", client: &reqwest_client).await?;
    /// ```
    ///
    pub async fn login(
        &self,
        host: &str,
        client: &reqwest::Client,
    ) -> Result<UniversalAuthAccessToken, Box<dyn std::error::Error>> {
        let auth_login_url = format!("{}/api/{}/auth/universal-auth/login", host, &self.version);

        // much cleaner way of constructing reqwest headers and json data and...whatever else in the future
        let mut universal_auth_data_headers = HeaderMap::new();
        universal_auth_data_headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // much cleaner way of constructing reqwest headers and json data and...whatever else in the future
        let mut universal_auth_data = HashMap::new();

        universal_auth_data.insert("clientId", &self.client_id);
        universal_auth_data.insert("clientSecret", &self.client_secret);

        let response = client
            .post(&auth_login_url)
            .headers(universal_auth_data_headers)
            .json(&universal_auth_data)
            .send()
            .await?;

        // for error handling / reporting
        let response_status = response.status().to_string();

        // if response doesnt return a 200 OK, short circuit and return a ApiResponse
        if response.status().ne(&StatusCode::OK) {
            let error_response = response.json::<ApiResponseEnum>().await?;

            #[cfg(not(feature = "logging_silent"))]
            println!("error_response: {}", error_response.to_string());

            return Err(Box::new(UniversalAuthError::UniversalAuthLoginError {
                client_id: self.client_id.clone(),
                client_identity_id: self.identity_id.clone(),
                version: self.version.clone(),
                response_status,
                access_token_error: either::Right(error_response.to_string()),
            }));
        }

        let bytes = response.bytes().await?;

        match serde_json::from_slice::<UniversalAuthAccessTokenData>(&bytes) {
            Ok(access_token) => Ok(UniversalAuthAccessToken {
                data: SecretBox::new(Box::new(access_token)),
                version: self.version.clone(),
            }),
            Err(access_token_error) => {
                println!("access_token_error");
                return Err(Box::new(UniversalAuthError::UniversalAuthLoginError {
                    client_id: self.client_id.clone(),
                    client_identity_id: self.identity_id.clone(),
                    version: self.version.clone(),
                    response_status,
                    access_token_error: either::Left(access_token_error),
                }));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------

/// Universal Auth Access Token functionality begins here
impl UniversalAuthAccessToken {
    // convenience functions to keep things below DRYer
    async fn construct_universal_auth_identity_endpoint_url(
        &self,
        host: &str,
        identity_id: &str,
    ) -> String {
        format!(
            "{host_url}/api/{version}/auth/universal-auth/identities/{identity_id}",
            host_url = host,
            version = &self.version,
            identity_id = identity_id
        )
    }

    async fn construct_universal_client_secret_url(
        &self,
        host: &str,
        identity_id: &str,
        client_secret_id: Option<&str>,
    ) -> String {
        let is_client_secret = client_secret_id.map_or_else(
            || "".to_string(),
            |client_secret| format!("/{client_secret}"),
        );

        format!(
            "{host_url}/api/{version}/auth/universal-auth/identities/{identity_id}/client-secrets{client_secret_id}",
            host_url = host,
            version = &self.version,
            identity_id = identity_id,
            client_secret_id = is_client_secret
        )
    }

    // ***************************
    /// UniversalAuth::Attach
    /// app_config
    pub async fn attach(
        &self,
        host: &str,
        client: &reqwest::Client,
        identity_to_attach_to: &str,
        client_secret_trusted_ips: Option<&Vec<(String, IpAddr)>>,
        access_token_trusted_ips: Option<&Vec<(String, IpAddr)>>,
        access_token_time_to_live: Option<u32>,
        access_token_max_time_to_live: Option<u32>,
        access_token_num_uses_limit: Option<u128>,
    ) -> Result<IndentityUniversalAuth, Box<dyn std::error::Error>> {
        let endpoint_url = &self
            .construct_universal_auth_identity_endpoint_url(&host, identity_to_attach_to)
            .await;

        // construct request headers
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut trusted_ips_config_form_data = HashMap::new();

        // set up client secret and access tokens trusted IPs in request form
        // im fairly sure this is an Infisical Pro-only feature, and will default to 0.0.0.0 and ::0 for both fields and ignore user inputs
        // regardless of user input on free plans
        if client_secret_trusted_ips.is_none() {
            // check for user client secret trusted IPs
            trusted_ips_config_form_data.insert(
                "clientSecretTrustedIpsStruct",
                default_client_secret_trusted_ip_vector(),
            );
        } else if access_token_trusted_ips.is_none() {
            trusted_ips_config_form_data.insert(
                "accessTokenTrustedIpsStruct",
                default_access_token_trusted_ip_vector(),
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

        let mut access_token_config_form_data = HashMap::new();

        // set up access token time-to-live, max time-to-live, and number of uses
        // note: the magic numbers are Infisical's default values for this field (equivalent to 30 days by default), so ask them
        access_token_config_form_data.insert(
            "accessTokenTTL",
            serde_json::to_value(access_token_time_to_live.unwrap_or_else(|| 2592000))?,
        );
        // note: the magic numbers are Infisical's default values for this field (equivalent to 30 days by default,), so ask them
        access_token_config_form_data.insert(
            "accessTokenMaxTTL",
            serde_json::to_value(access_token_max_time_to_live.unwrap_or_else(|| 2592000))?,
        );
        // note: the magic numbers are Infisical's default values for this field (equivalent to 0 limits on number of usage, or unlimited usage), so ask them
        access_token_config_form_data.insert(
            "accessTokenNumUsesLimit",
            serde_json::to_value(access_token_num_uses_limit.unwrap_or_else(|| 0))?,
        );

        // reqwest HTTP response
        let response = client
            .post(endpoint_url)
            .bearer_auth(&self.access_token())
            .headers(headers)
            .json(&trusted_ips_config_form_data)
            .json(&access_token_config_form_data)
            .send()
            .await?;

        // print HTTP response for user posterity
        println!(
            "Universal Auth Attach() for {} HTTP response: {}",
            identity_to_attach_to,
            response.status().to_string()
        );

        let bytes = response.bytes().await?;
        let unescaped = reqwest_bytes_to_unescaped_string(&bytes)?;
        println!(
            "universalauth::attach bytes(): \n\
        {}\n",
            unescaped
        );

        // attempt to deserialize HTTP response into a compatible Rust struct for...
        // rust things where you would need this

        match serde_json::from_slice::<IndentityUniversalAuth>(&bytes) {
            Ok(uauth_identity_data) => {
                println!(
                    "ex: {}",
                    uauth_identity_data
                        .identity_universal_auth
                        .expose_secret()
                        .access_token_max_ttl
                );
                Ok(uauth_identity_data)
            }
            Err(struct_error) => return Err(format!("struct_error: {:#?}", struct_error).into()),
        }
    }

    pub async fn retrieve(
        &self,
        host: &str,
        client: &reqwest::Client,
        identity_to_retrieve: &str,
        access_token: &UniversalAuthAccessToken,
    ) -> Result<IndentityUniversalAuth, Box<dyn std::error::Error>> {
        let endpoint_url = format!(
            "{host_url}/api/{version}/auth/universal-auth/identities/{identity_id}",
            host_url = host,
            version = &self.version,
            identity_id = identity_to_retrieve
        );
        let response = client
            .get(endpoint_url)
            .bearer_auth(access_token.access_token())
            .send()
            .await?;

        let response_status = response.status().to_string();
        println!(
            "Universal Auth retrieve() response for {}: {}",
            identity_to_retrieve, response_status
        );

        match response.json::<IndentityUniversalAuth>().await {
            Ok(retrieved_configuration) => return Ok(retrieved_configuration),
            Err(e) => return Err(Box::new(e)),
        };

        // todo!()
    }

    // this is 99.99% the exaxt same code as attach() above outside of calling reqwest::patch instead of request::post,
    // so the majority of that function's logic carries over to here
    pub async fn update(
        &self,
        host: &str,
        client: &reqwest::Client,
        identity_to_update: &str,
        client_secret_trusted_ips: Option<&Vec<(String, IpAddr)>>,
        access_token_trusted_ips: Option<&Vec<(String, IpAddr)>>,
        access_token_time_to_live: Option<u32>,
        access_token_max_time_to_live: Option<u32>,
        access_token_num_uses_limit: Option<u128>,
    ) -> Result<IndentityUniversalAuth, Box<dyn std::error::Error>> {
        let endpoint_url = self
            .construct_universal_auth_identity_endpoint_url(host, identity_to_update)
            .await;

        // construct request headers
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut trusted_ips_config_form_data = HashMap::new();

        // set up client secret and access tokens trusted IPs in request form
        // im fairly sure this is an Infisical Pro-only feature, and will default to 0.0.0.0 and ::0 for both fields and ignore user inputs
        // regardless of user input on free plans
        if client_secret_trusted_ips.is_none() {
            // check for user client secret trusted IPs
            trusted_ips_config_form_data.insert(
                "clientSecretTrustedIpsStruct",
                default_client_secret_trusted_ip_vector(),
            );
        } else if access_token_trusted_ips.is_none() {
            trusted_ips_config_form_data.insert(
                "accessTokenTrustedIpsStruct",
                default_access_token_trusted_ip_vector(),
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

        let mut access_token_config_form_data = HashMap::new();

        // set up access token time-to-live, max time-to-live, and number of uses
        // note: the magic numbers are Infisical's default values for this field (equivalent to 30 days by default), so ask them
        access_token_config_form_data.insert(
            "accessTokenTTL",
            serde_json::to_value(access_token_time_to_live.unwrap_or_else(|| 2592000))?,
        );
        // note: the magic numbers are Infisical's default values for this field (equivalent to 30 days by default,), so ask them
        access_token_config_form_data.insert(
            "accessTokenMaxTTL",
            serde_json::to_value(access_token_max_time_to_live.unwrap_or_else(|| 2592000))?,
        );
        // note: the magic numbers are Infisical's default values for this field (equivalent to 0 limits on number of usage, or unlimited usage), so ask them
        access_token_config_form_data.insert(
            "accessTokenNumUsesLimit",
            serde_json::to_value(access_token_num_uses_limit.unwrap_or_else(|| 0))?,
        );

        // reqwest HTTP response
        let response = client
            .patch(endpoint_url)
            .bearer_auth(&self.access_token())
            .headers(headers)
            .json(&trusted_ips_config_form_data)
            .json(&access_token_config_form_data)
            .send()
            .await?;

        // print HTTP response for user posterity
        println!(
            "Universal Auth Update() for {} HTTP response: {}",
            identity_to_update,
            response.status().to_string()
        );

        // attempt to deserialize HTTP response into a compatible Rust struct for...
        // rust things where you would need this
        match response.json::<IndentityUniversalAuth>().await {
            Ok(uauth_identity_data) => {
                println!(
                    "ex: {}",
                    uauth_identity_data
                        .identity_universal_auth
                        .expose_secret()
                        .access_token_max_ttl
                );
                Ok(uauth_identity_data)
            }
            Err(struct_error) => {
                return Err(Box::new(UniversalAuthError::UpdateIdentityError {
                    error: struct_error,
                }));
            }
        }
        // todo!()
    }

    pub async fn revoke(
        &self,
        host: &str,
        client: &reqwest::Client,
        identity_to_revoke: &str,
    ) -> Result<IndentityUniversalAuth, Box<dyn std::error::Error>> {
        let endpoint_url = self
            .construct_universal_auth_identity_endpoint_url(&host, identity_to_revoke)
            .await;

        // let r;
        let response = client
            .delete(endpoint_url)
            .bearer_auth(&self.access_token())
            .send()
            .await?;

        // print HTTP response for user posterity
        println!(
            "Universal Auth Revoke() for {} HTTP response: {}",
            identity_to_revoke,
            response.status().to_string()
        );

        match response.json::<IndentityUniversalAuth>().await {
            Ok(uauth_identity_data) => {
                println!(
                    "ex: {}",
                    uauth_identity_data
                        .identity_universal_auth
                        .expose_secret()
                        .access_token_max_ttl
                );
                Ok(uauth_identity_data)
            }
            Err(struct_error) => {
                return Err(Box::new(UniversalAuthError::RevokeClientSecretError {
                    error: struct_error.without_url(),
                }));
            }
        }
    }

    pub async fn create_client_secret(
        &self,
        host: &str,
        client: &reqwest::Client,
        identity_id: &str,
        client_secret_description: &str,
        client_secret_num_uses_limit: u64,
        client_secret_time_to_live: u64,
    ) -> Result<UniversalAuthClientSecret, Box<dyn std::error::Error>> {
        // ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let endpoint_url = self
            .construct_universal_client_secret_url(&host, identity_id, None)
            .await;

        // println!("create_client_secret url: {endpoint_url}");
        // let mut description_data = HashMap::new();
        let mut form_data = HashMap::new();

        // description_data.insert("description", "client_secret_description");
        form_data.insert("numUsesLimit", client_secret_num_uses_limit);
        form_data.insert("ttl", client_secret_time_to_live);

        // let build = &reqwest::Client::new()
        //     .post(&endpoint_url)
        //     .bearer_auth(&self.access_token())
        //     .header(CONTENT_TYPE, "application/json")
        //     .json(&[("description", client_secret_description.to_string())])
        //     .json(&form_data)
        //     .build()?;

        // let f = build.body().;

        // // println!("create_client_secret")

        // let response = client.execute(build).await?;
        let response = client
            .post(&endpoint_url)
            .bearer_auth(&self.access_token())
            .header(CONTENT_TYPE, "application/json")
            .json(&[("description", client_secret_description.to_string())])
            .json(&form_data)
            .send()
            .await?;

        // print HTTP response for user posterity
        println!(
            "Universal Auth create_client_secret() for {} HTTP response: {}",
            identity_id,
            response.status().to_string(),
        );

        let bytes = response.bytes().await?;

        println!("create_client_secret bytes: {bytes:#?}");
        match serde_json::from_slice::<UniversalAuthClientSecret>(&bytes) {
            Ok(client_secret) => Ok(client_secret),
            Err(e) => Err(Box::new(UniversalAuthError::CreateClientSecretError {
                error: e,
            })),
        }
        // todo!("implement UniversalAuth::create_client_secret()")
    }

    pub async fn revoke_client_secret(
        &self,
        host: &str,
        client: &reqwest::Client,
        identity_id: &str,
        client_secret_to_revoke: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let endpoint_url = format!(
            "{}/revoke",
            self.construct_universal_client_secret_url(
                &host,
                identity_id,
                Some(client_secret_to_revoke),
            )
            .await
        );

        println!("revoke_client_secret: {endpoint_url}");

        let response = client
            .post(&endpoint_url)
            .bearer_auth(&self.access_token())
            .send()
            .await?;

        let bytes = response.bytes().await?;
        println!("revoke_client_secret bytes: {bytes:#?}");

        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(revoked_client_secret) => Ok(revoked_client_secret),
            Err(e) => Err(Box::new(e)),
        }
    }

    pub async fn get_client_secret_by_id(
        &self,
        host: &str,
        client: &reqwest::Client,
        identity_id: &str,
        client_secret_id: &str,
    ) -> Result<UniversalAuthClientSecretData, Box<dyn std::error::Error>> {
        let endpoint_url = format!(
            "{}/revoke",
            self.construct_universal_client_secret_url(&host, identity_id, Some(client_secret_id),)
                .await
        );

        let response = client
            .get(&endpoint_url)
            .bearer_auth(self.access_token())
            .send()
            .await?;

        let bytes = response.bytes().await?;
        println!("get_client_secret_by_id bytes: {bytes:#?}");

        match serde_json::from_slice::<UniversalAuthClientSecretData>(&bytes) {
            Ok(client_secret) => Ok(client_secret),
            Err(e) => Err(Box::new(e)),
        }
        // todo!()
    }
}
// ---------------------------------------------------------------------------------------------------------
// impl UAuthSecrecyStruct
// ---------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------
// getters for SecretBox-wrapped access token, since writing access_token.data.expose_secret().[field] gets annoying REALLY fast
impl Display for UniversalAuthCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "
            Client ID: {}
            Client Secret: {}
            Client Identity ID: {}
            Universal Auth API Version: {}
            ",
            self.client_id, "*************", self.identity_id, self.version
        )
    }
}

impl Debug for UniversalAuthCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UniversalAuthCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"************")
            .field("identity_id", &self.identity_id)
            .field("version", &self.version)
            .finish()
    }
}

impl UniversalAuthAccessToken {
    pub fn access_token(&self) -> &str {
        &self.data.expose_secret().access_token
    }
    pub fn access_token_max_ttl(&self) -> u64 {
        self.data.expose_secret().access_token_max_ttl
    }
    pub fn expires_in(&self) -> u64 {
        self.data.expose_secret().expires_in
    }
    pub fn token_type(&self) -> &str {
        &self.data.expose_secret().token_type
    }
}

impl Default for UniversalAuthAccessTokenData {
    fn default() -> Self {
        Self {
            access_token: Default::default(),
            access_token_max_ttl: Default::default(),
            expires_in: Default::default(),
            token_type: Default::default(),
        }
    }
}

impl SerializableSecret for UniversalAuthAccessTokenData {}
impl Zeroize for UniversalAuthAccessTokenData {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        self.access_token_max_ttl.zeroize();
        self.expires_in.zeroize();
        self.token_type.zeroize();
    }
}

impl Display for UniversalAuthAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "
        access token: ********************
        Access Token Time To Live: {}
        Access Token Max Time To Live: {}
        Access Token Type: {}
        ",
            self.expires_in(),
            self.access_token_max_ttl(),
            self.token_type()
        )
    }
}

// ---------------------------------------------------------------------------------------------------------
// Universal Auth Client Secret Implementations

impl SerializableSecret for UniversalAuthClientSecretData {}

impl Zeroize for UniversalAuthClientSecretData {
    fn zeroize(&mut self) {
        self.client_secret_num_uses.zeroize();
        self.client_secret_num_uses_limit.zeroize();
        self.client_secret_prefix.zeroize();
        self.client_secret_ttl.zeroize();
        self.created_at.zeroize();
        self.description.zeroize();
        self.id.zeroize();
        self.identity_ua_id.zeroize();
        self.is_client_secret_revoked.zeroize();
        self.updated_at.zeroize();
    }
}

impl Display for UniversalAuthClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
        // write!(f, "")
    }
}

// impl Debug for UniversalAuthClientSecret {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("UniversalAuthClientSecret")
//             .field("client_secret", &self.client_secret)
//             .field("client_secret_data", &self.client_secret_data)
//             .finish()
//     }
// }
// ---------------------------------------------------------------------------------------------------------
impl SerializableSecret for IndentityUniversalAuthData {}
impl Zeroize for IndentityUniversalAuthData {
    fn zeroize(&mut self) {
        self.access_token_max_ttl.zeroize();
        self.access_token_num_uses_limit.zeroize();
        self.access_token_ttl.zeroize();
        self.access_token_trusted_ips
            .iter_mut()
            .for_each(|ip_elem| {
                ip_elem.ip_address.zeroize();
                ip_elem.prefix.zeroize();
                ip_elem.type_.zeroize();
            });
        self.client_id.zeroize();
        self.client_secret_trusted_ips
            .iter_mut()
            .for_each(|ip_elem| {
                ip_elem.ip_address.zeroize();
                ip_elem.prefix.zeroize();
                ip_elem.type_.zeroize();
            });
        self.created_at.zeroize();
        self.id.zeroize();
        self.identity_id.zeroize();
        self.updated_at.zeroize();
    }
}
