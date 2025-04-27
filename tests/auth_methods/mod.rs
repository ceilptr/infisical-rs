use infisical_rs::utils::api_utils::{AccessTokenTrustedIp, ClientSecretTrustedIp};

pub mod universal_auth_tests;

// thanks, internet: https://stackoverflow.com/questions/29504514/whats-the-best-way-to-compare-2-vectors-or-strings-element-by-element
pub fn test_default_trusted_ips(
    access_token_trusted_ips: &Vec<AccessTokenTrustedIp>,
    client_secret_trusted_ips: &Vec<ClientSecretTrustedIp>,
) -> bool {
    let default_access_token_trusted_ips: Vec<AccessTokenTrustedIp> = vec![
        AccessTokenTrustedIp::default_ipv4(),
        AccessTokenTrustedIp::default_ipv6(),
    ];

    let default_client_secret_trusted_ips: Vec<ClientSecretTrustedIp> = vec![
        ClientSecretTrustedIp::default_ipv4(),
        ClientSecretTrustedIp::default_ipv6(),
    ];

    // thanks, internet: https://stackoverflow.com/questions/29504514/whats-the-best-way-to-compare-2-vectors-or-strings-element-by-element

    let match_access_token_trusted_ips = access_token_trusted_ips
        .iter()
        .zip(default_access_token_trusted_ips.iter())
        .filter(|&(uauth_identity_ip, default_ip)| uauth_identity_ip.eq(default_ip))
        .count();

    let match_client_secret_trusted_ips = client_secret_trusted_ips
        .iter()
        .zip(default_client_secret_trusted_ips.iter())
        .filter(|&(uauth_identity_ip, default_ip)| uauth_identity_ip.eq(default_ip))
        .count();

    // assert access_token and client_secret trusted ips were constructed correctly
    if !(match_access_token_trusted_ips.eq(&access_token_trusted_ips.len())
        && match_access_token_trusted_ips.eq(&default_access_token_trusted_ips.len()))
    {
        return false;
    }

    // assert access_token and client_secret trusted ips were constructed correctly
    if !(match_client_secret_trusted_ips.eq(&client_secret_trusted_ips.len())
        && match_client_secret_trusted_ips.eq(&default_client_secret_trusted_ips.len()))
    {
        return false;
    }

    true
}
