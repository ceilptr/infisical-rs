#[cfg(test)]
pub mod universal_auth_tests {
    pub mod create_auth_method {
        use infisical_rs::infisical::auth_methods::universal_auth::utils::UniversalAuthCredentials;

        fn empty_auth_credentials() -> UniversalAuthCredentials {
            UniversalAuthCredentials {
                client_id: "".to_string(),
                client_secret: "".to_string(),
                identity_id: "".to_string(),
                version: "".to_string(),
            }
        }

        fn mock_auth_credentials() -> UniversalAuthCredentials {
            UniversalAuthCredentials {
                client_id: "TEST_CLIENT_ID".to_string(),
                client_secret: "TEST_CLIENT_SECRET".to_string(),
                identity_id: "TEST_MACHINE_IDENTITY_ID".to_string(),
                version: "v1".to_string(),
            }
        }

        #[test]
        fn test_empty_auth_credentials() {
            let credentials = empty_auth_credentials();

            assert_eq!(credentials.client_id, "");
            assert_eq!(credentials.client_secret, "");
            assert_eq!(credentials.identity_id, "");
            assert_eq!(credentials.version, "");
        }

        #[test]
        fn test_mock_auth_credentials() {
            let credentials = mock_auth_credentials();

            assert_eq!(credentials.client_id, "TEST_CLIENT_ID");
            assert_eq!(credentials.client_secret, "TEST_CLIENT_SECRET");
            assert_eq!(credentials.identity_id, "TEST_MACHINE_IDENTITY_ID");
            assert_eq!(credentials.version, "v1");
        }
    }

    #[tokio::test]
    async fn login() {
        todo!("implement login test")
    }
}
