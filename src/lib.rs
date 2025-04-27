// #![deny(missing_docs)]

//! the pain of deny(missing_docs) begins here
//! Rustlang binding for the [infisical](https://infisical.com/) [api reference](https://infisical.com/docs/api-reference/overview/introduction).
//!
//!

/// module containing the various authentication methods (token auth, Google Cloud Platform auth, etc)
pub mod auth_methods;
/// various internal odds and ends to uphold DRY principles
pub mod utils;

/// all those arbitrary magic numbers that keep popping up (angel numbers not included)
pub mod infisical_constants {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// by default, Infisical uses the magic number 2592000 (equivalent to 30 days in seconds) as as baseline for multiple values,
    /// including access token time-to-live, max time-to-live, etc
    pub const INFISICAL_DEFAULT_TIME_TO_LIVE: u128 = 2592000;

    /// within certain operations (mainly to do with anything involving trusted IPs, e.g., universal_auth::attach() ), Infisical uses 0.0.0.0 as a default ipv4 value.
    /// Note that any API requests will ignore user-set trusted IP addresses unless they are on an Infisical Pro plan.
    pub const INFISICAL_DEFAULT_IPV4_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

    /// within certain operations (mainly to do with anything involving trusted IPs, e.g., universal_auth::attach() ), Infisical uses ::0 as a default ipv6 value.
    /// Note that any API requests will ignore user-set trusted IP addresses unless they are on an Infisical Pro plan.
    pub const INFISICAL_DEFAULT_IPV6_ADDRESS: IpAddr =
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
}
