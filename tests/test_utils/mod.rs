use std::sync::LazyLock;
// use std::sync::OnceLock;

use infisical_rs::infisical::utils::api_utils::AppConfig;
// link to environment variables here
// pub mod user_test_env;
pub mod _env;

// struct TestUtilSetup {
//     host: String,
//     app_config: LazyLock<AppConfig>,
// }
pub static TEST_CLOUD_HOST: &str = "https://us.infisical.com";
pub static TEST_USER_HOST: &str = "";

pub static INIT_CLOUD_APPCONFIG: LazyLock<AppConfig> = LazyLock::new(|| AppConfig {
    host: TEST_CLOUD_HOST.to_string(),
    client: reqwest::Client::new(),
});

pub fn set_environment_variables() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv()?;
    Ok(())
}

pub mod universal_auth_test_utils {
    use std::sync::LazyLock;

    use infisical_rs::infisical::auth_methods::universal_auth::utils::{
        UniversalAuthAccessToken, UniversalAuthCredentials,
    };

    use super::_env::{
        TEST_ATTACH_IDENTITY_ID, TEST_CLIENT_ID, TEST_CLIENT_SECRET, UNIVERSAL_AUTH_TESTING_STATION,
    };

    pub static UNIVERSAL_AUTH_TEST_EMPTY_CREDENTIALS: LazyLock<UniversalAuthCredentials> =
        LazyLock::new(|| UniversalAuthCredentials {
            client_id: "".to_string(),
            client_secret: "".to_string(),
            identity_id: "".to_string(),
            version: "".to_string(),
        });

    pub static UNIVERSAL_AUTH_TEST_INCORRECT_CREDENTIALS: LazyLock<UniversalAuthCredentials> =
        LazyLock::new(|| UniversalAuthCredentials {
            client_id: "TEST_CLIENT_ID".to_string(),
            client_secret: "TEST_CLIENT_SECRET".to_string(),
            identity_id: "TEST_CLIENT_IDENTITY_ID".to_string(),
            version: "v0".to_string(),
        });

    pub static UNIVERSAL_AUTH_TEST_MOCK_CREDENTIALS: LazyLock<UniversalAuthCredentials> =
        LazyLock::new(|| UniversalAuthCredentials {
            client_id: (*TEST_CLIENT_ID.clone()).to_string(),
            client_secret: (*TEST_CLIENT_SECRET.clone()).to_string(),
            identity_id: (*TEST_ATTACH_IDENTITY_ID.clone()).to_string(),
            version: "v1".to_string(),
        });

    pub fn universal_auth_test_setup() {}

    pub async fn mock_access_token_login()
    -> Result<UniversalAuthAccessToken, Box<dyn std::error::Error>> {
        let config = &*UNIVERSAL_AUTH_TESTING_STATION;
        Ok(config
            .credentials
            .login(&config.config.host, &config.config.client)
            .await?)
    }
}
