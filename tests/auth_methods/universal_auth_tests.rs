#[cfg(test)]
pub mod universal_auth_tests {

    pub mod login {

        use infisical_rs::{auth_methods::universal_auth::*, infisical_constants::*};

        use crate::test_utils;

        #[tokio::test]
        async fn login() -> Result<(), error_handling::UniversalAuthError> {
            let test_struct = &*test_utils::_env::UNIVERSAL_AUTH_TESTING_STATION;

            let access_token = test_struct
                .credentials
                .login(&test_struct.config.host, &test_struct.config.client)
                .await
                .or_else(|e| return Err(e))?;

            assert!(!access_token.access_token().is_empty());
            assert!(
                access_token
                    .access_token_max_ttl()
                    .ge(&INFISICAL_DEFAULT_TIME_TO_LIVE)
            );
            assert!(
                access_token
                    .expires_in()
                    .eq(&INFISICAL_DEFAULT_TIME_TO_LIVE)
            );
            assert!(!access_token.version.is_empty());
            Ok(())
            // todo!("implement login test")
        }
    }

    pub mod access_token_testing {

        pub mod test_attach {

            use infisical_rs::{
                auth_methods::universal_auth::error_handling::UniversalAuthError,
                infisical_constants::*,
            };

            /// test_attach_default
            ///
            /// Expected: Ok(IndentityUniversalAuth)
            ///
            /// note: This test will fail if said identity already has a Universal Auth configuration. This is expected behaviour, and is addressed in the next test
            use crate::{
                auth_methods::test_default_trusted_ips,
                test_utils::{self, universal_auth_test_utils::mock_access_token_login},
            };

            #[tokio::test]
            async fn test_attach_default() -> Result<(), UniversalAuthError> {
                let config = &*test_utils::_env::UNIVERSAL_AUTH_TESTING_STATION;
                let access_token = mock_access_token_login(config).await?;

                let test_identity = &*test_utils::_env::TEST_ATTACH_IDENTITY_ID;

                let _revoked_identity = access_token
                    .revoke(&config.config.host, &config.config.client, test_identity)
                    .await?;

                let configured_uauth_identity = access_token
                    .attach(
                        &config.config.host,
                        &config.config.client,
                        &*test_utils::_env::TEST_ATTACH_IDENTITY_ID,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;

                assert_ne!(configured_uauth_identity.id().is_empty(), true);
                assert_ne!(configured_uauth_identity.client_id().is_empty(), true);
                assert_eq!(*configured_uauth_identity.access_token_ttl(), 0);
                assert_eq!(*configured_uauth_identity.access_token_max_ttl(), 0);
                assert_eq!(*configured_uauth_identity.access_token_num_uses_limit(), 0);
                assert_eq!(
                    test_default_trusted_ips(
                        configured_uauth_identity.access_token_trusted_ips(),
                        configured_uauth_identity.client_secret_trusted_ips()
                    ),
                    true
                );
                assert_ne!(configured_uauth_identity.created_at().is_empty(), true);
                assert_ne!(configured_uauth_identity.updated_at().is_empty(), true);
                assert_ne!(configured_uauth_identity.identity_id().is_empty(), true);

                todo!("implement test_attach()")
            }

            #[tokio::test]
            async fn test_already_attached_config() -> Result<(), Box<dyn std::error::Error>> {
                let config = &*test_utils::_env::UNIVERSAL_AUTH_TESTING_STATION;
                let access_token = mock_access_token_login(config).await?;

                let test_identity = &*test_utils::_env::TEST_ATTACH_IDENTITY_ID;

                let configured_identity = access_token
                    .attach(
                        &config.config.host,
                        &config.config.client,
                        test_identity,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;

                assert!(
                    configured_identity
                        .access_token_max_ttl()
                        .ge(&INFISICAL_DEFAULT_TIME_TO_LIVE)
                );

                todo!()
                // Ok(())
            }
        }
        pub mod test_retrieve {
            use infisical_rs::{
                auth_methods::universal_auth::error_handling::UniversalAuthError,
                infisical_constants::*,
            };

            use crate::test_utils::{
                _env::{TEST_ATTACH_IDENTITY_ID, UNIVERSAL_AUTH_TESTING_STATION},
                universal_auth_test_utils::mock_access_token_login,
            };

            #[tokio::test]
            async fn test_default_retrieve() -> Result<(), UniversalAuthError> {
                let config = &*UNIVERSAL_AUTH_TESTING_STATION;
                let access_token = mock_access_token_login(&config).await?;

                let retrieved_identity = access_token
                    .retrieve(
                        &config.config.host,
                        &config.config.client,
                        &*TEST_ATTACH_IDENTITY_ID,
                    )
                    .await?;

                assert_eq!(
                    *retrieved_identity.access_token_max_ttl(),
                    INFISICAL_DEFAULT_TIME_TO_LIVE
                );

                assert_eq!(*retrieved_identity.access_token_num_uses_limit(), 0);

                assert_eq!(
                    *retrieved_identity.access_token_ttl(),
                    INFISICAL_DEFAULT_TIME_TO_LIVE
                );

                Ok(())
            }

            #[tokio::test]
            async fn test_retrieve_config() -> Result<(), UniversalAuthError> {
                let testing_station = &*UNIVERSAL_AUTH_TESTING_STATION;
                let access_token = mock_access_token_login(testing_station).await?;

                let retrieved_identity = access_token
                    .retrieve(
                        &testing_station.config.host,
                        &testing_station.config.client,
                        &*TEST_ATTACH_IDENTITY_ID,
                    )
                    .await?;

                assert_eq!(
                    *retrieved_identity.access_token_max_ttl(),
                    INFISICAL_DEFAULT_TIME_TO_LIVE
                );

                assert_eq!(
                    *retrieved_identity.access_token_ttl(),
                    INFISICAL_DEFAULT_TIME_TO_LIVE
                );

                assert_eq!(*retrieved_identity.access_token_num_uses_limit(), 0);

                assert_ne!(retrieved_identity.client_id().is_empty(), true);
                Ok(())
            }
        }
        pub mod test_revoke {
            use infisical_rs::auth_methods::universal_auth::error_handling::UniversalAuthError;

            use crate::test_utils::{
                _env::{TEST_ATTACH_IDENTITY_ID, UNIVERSAL_AUTH_TESTING_STATION},
                universal_auth_test_utils::mock_access_token_login,
            };

            #[tokio::test]
            async fn revoke_identity_config() -> Result<(), UniversalAuthError> {
                let config = &*UNIVERSAL_AUTH_TESTING_STATION;
                let access_token = mock_access_token_login(&config).await?;

                let revoked_identity_config = access_token
                    .revoke(
                        &config.config.host,
                        &config.config.client,
                        &*TEST_ATTACH_IDENTITY_ID,
                    )
                    .await?;

                todo!()
                // Ok(())
            }

            #[tokio::test]
            async fn revoke_clent_secret() -> Result<(), UniversalAuthError> {
                Ok(())
            }
        }
    }
}
