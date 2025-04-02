#[cfg(test)]
pub mod universal_auth_tests {
    use crate::test_utils::{self, set_environment_variables};

    pub mod create_auth_method {
        use infisical_rs::infisical::auth_methods::universal_auth::utils::UniversalAuthCredentials;

        use crate::test_utils;

        pub fn empty_auth_credentials() -> UniversalAuthCredentials {
            UniversalAuthCredentials {
                client_id: "".to_string(),
                client_secret: "".to_string(),
                identity_id: "".to_string(),
                version: "".to_string(),
            }
        }

        pub fn mock_auth_credentials() -> UniversalAuthCredentials {
            UniversalAuthCredentials {
                client_id: (*test_utils::test_env::TEST_CLIENT_ID.clone()).to_string(),
                client_secret: "TEST_CLIENT_SECRET".to_string(),
                identity_id: "TEST_MACHINE_IDENTITY_ID".to_string(),
                version: "v1".to_string(),
            }
        }

        pub fn incorrect_auth_credentials() -> UniversalAuthCredentials {
            UniversalAuthCredentials {
                client_id: "TEST_CLIENT_ID".to_string(),
                client_secret: "TEST_CLIENT_SECRET".to_string(),
                identity_id: "TEST_MACHINE_IDENTITY_ID".to_string(),
                version: "v1".to_string(),
            }
        }

        #[test]
        pub fn test_empty_auth_credentials() {
            let credentials = empty_auth_credentials();

            assert_eq!(credentials.client_id, "");
            assert_eq!(credentials.client_secret, "");
            assert_eq!(credentials.identity_id, "");
            assert_eq!(credentials.version, "");
        }

        #[test]
        fn test_mock_auth_credentials() {
            let credentials = mock_auth_credentials();

            assert_eq!(credentials.client_id, *test_utils::test_env::TEST_CLIENT_ID);
            // assert_eq!(credentials.client_secret, "TEST_CLIENT_SECRET");
            // assert_eq!(credentials.identity_id, "TEST_MACHINE_IDENTITY_ID");
            // assert_eq!(credentials.version, "v1");
        }
    }

    pub mod login {
        use infisical_rs::infisical::utils::api_utils::AppConfig;

        use crate::{
            auth_methods::universal_auth_tests::universal_auth_tests::create_auth_method::mock_auth_credentials,
            test_utils,
        };

        #[tokio::test]
        async fn login() {
            // match dotenvy::dotenv() {
            //     Ok(env_vars) => todo!(),
            //     Err(_) => todo!(),
            // }

            let config = &*test_utils::INIT_CLOUD_APPCONFIG;
            let credentials = mock_auth_credentials();

            match credentials.login(&config.host, &config.client).await {
                Ok(access_token) => {
                    assert!(!access_token.access_token().is_empty());
                    assert!(!access_token.access_token_max_ttl().ge(&0));
                    assert!(!access_token.expires_in().ge(&0));
                    assert!(!access_token.version.is_empty());
                }
                Err(e) => {}
            }

            todo!("implement login test")
        }
    }

    #[test]
    fn test_env_vars_0() {
        set_environment_variables().ok();
        for (key, value) in std::env::vars() {
            println!("${key}: ${value}");
        }
        assert_eq!(std::env::var("TEST_ATTACH_IDENTITY_ID").is_ok(), true);
    }
}
