#[cfg(test)]
pub mod universal_auth_tests {
    use crate::test_utils::{self, set_environment_variables};

    pub mod login {
        use infisical_rs::infisical::{
            DEFAULT_INFISICAL_MAX_VAL,
            auth_methods::universal_auth::utils::UniversalAuthAccessToken,
        };

        use crate::test_utils;

        #[tokio::test]
        async fn login() -> Result<(), Box<dyn std::error::Error>> {
            let test_struct = &*test_utils::_env::UNIVERSAL_AUTH_TESTING_STATION;

            match test_struct
                .credentials
                .login(&test_struct.config.host, &test_struct.config.client)
                .await
            {
                Ok(access_token) => {
                    assert!(!access_token.access_token().is_empty());
                    assert!(
                        access_token
                            .access_token_max_ttl()
                            .ge(&DEFAULT_INFISICAL_MAX_VAL)
                    );
                    assert!(access_token.expires_in().eq(&DEFAULT_INFISICAL_MAX_VAL));
                    assert!(!access_token.version.is_empty());
                    Ok(())
                }
                Err(e) => {
                    return Err(e);
                }
            }

            // todo!("implement login test")
        }
    }

    pub mod access_token_testing {
        pub mod test_attach {
            use infisical_rs::infisical::{
                DEFAULT_INFISICAL_MAX_VAL, INFISICAL_DEFAULT_IPV4_ADDRESS,
                INFISICAL_DEFAULT_IPV6_ADDRESS,
                auth_methods::universal_auth::utils::{
                    AccessTokenTrustedIp, AccessTokenTrustedIpsStruct, ClientSecretTrustedIpsStruct,
                },
            };
            use reqwest::header::Iter;

            use crate::test_utils::{self, universal_auth_test_utils::mock_access_token_login};
            #[tokio::test]
            async fn test_attach_default() -> Result<(), Box<dyn std::error::Error>> {
                let config = &*test_utils::_env::UNIVERSAL_AUTH_TESTING_STATION;

                let access_token = mock_access_token_login().await?;

                match access_token
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
                    .await
                {
                    Ok(uauth_identity) => {
                        assert_eq!(
                            *uauth_identity.access_token_max_ttl(),
                            DEFAULT_INFISICAL_MAX_VAL
                        );

                        assert_eq!(*uauth_identity.access_token_num_uses_limit(), 0);

                        assert_eq!(*uauth_identity.access_token_ttl(), 0);

                        let default_access_token_trusted_ips: Vec<AccessTokenTrustedIpsStruct> = vec![
                            AccessTokenTrustedIpsStruct::default_ipv4(),
                            AccessTokenTrustedIpsStruct::default_ipv6(),
                        ];

                        let default_client_secret_trusted_ips: Vec<ClientSecretTrustedIpsStruct> = vec![
                            ClientSecretTrustedIpsStruct::default_ipv4(),
                            ClientSecretTrustedIpsStruct::default_ipv6(),
                        ];

                        // thanks, internet: https://stackoverflow.com/questions/29504514/whats-the-best-way-to-compare-2-vectors-or-strings-element-by-element

                        let match_access_token_trusted_ips = uauth_identity
                            .access_token_trusted_ips()
                            .iter()
                            .zip(default_access_token_trusted_ips.iter())
                            .filter(|&(uauth_identity_ip, default_ip)| {
                                uauth_identity_ip.eq(default_ip)
                            })
                            .count();

                        let match_client_secret_trusted_ips = uauth_identity
                            .client_secret_trusted_ips()
                            .iter()
                            .zip(default_client_secret_trusted_ips.iter())
                            .filter(|&(uauth_identity_ip, default_ip)| {
                                uauth_identity_ip.eq(default_ip)
                            })
                            .count();

                        // assert access_token and client_secret trusted ips were constructed correctly
                        assert_eq!(
                            match_access_token_trusted_ips,
                            uauth_identity.access_token_trusted_ips().len()
                        );
                        assert_eq!(
                            match_access_token_trusted_ips,
                            default_access_token_trusted_ips.len()
                        );

                        assert_eq!(
                            match_client_secret_trusted_ips,
                            uauth_identity.client_secret_trusted_ips().len()
                        );
                        assert_eq!(
                            match_client_secret_trusted_ips,
                            default_client_secret_trusted_ips.len()
                        );

                        // the rest of the things to clean up
                        assert_ne!(uauth_identity.client_id().is_empty(), true);
                    }
                    Err(e) => return Err(e),
                }
                todo!("implement test_attach()")
            }
        }
    }
}
