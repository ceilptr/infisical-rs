use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod auth_methods;
pub mod utils;

pub const INFISICAL_DEFAULT_TIME_TO_LIVE: u128 = 2592000;
pub const INFISICAL_DEFAULT_IPV4_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
pub const INFISICAL_DEFAULT_IPV6_ADDRESS: IpAddr =
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
