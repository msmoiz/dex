use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};

use anyhow::{bail, Context};

/// The default port for a nameserver.
const DEFAULT_PORT: u16 = 53;

/// Resolves a nameserver string to a socket address.
///
/// The nameserver may be a hostname or IP address, with or without a port
/// (e.g., `8.8.8.8`, `8.8.8.8:53`, `fe80::1%en0`, `[fe80::1%en0]:53`). If no
/// port is given, the default DNS port is used. IPv6 addresses may include a
/// zone ID naming the interface to use, which is required for link-local
/// addresses.
pub fn resolve_nameserver(nameserver: &str) -> anyhow::Result<SocketAddr> {
    // bracketed ipv6, with a port
    if let Some(rest) = nameserver.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            bail!("invalid nameserver address");
        };
        let port = port.parse().context("invalid port value")?;
        return resolve_ipv6(host, port);
    }

    // bare ipv6, with no port.
    if nameserver.matches(':').count() > 1 {
        return resolve_ipv6(nameserver, DEFAULT_PORT);
    }

    // hostname or ipv4, with or without a port
    let (host, port) = match nameserver.split_once(':') {
        Some((host, port)) => (host, port.parse().context("invalid port value")?),
        None => (nameserver, DEFAULT_PORT),
    };

    (host, port)
        .to_socket_addrs()?
        .next()
        .context("no addresses found for nameserver")
}

/// Resolves an IPv6 address with an optional zone ID.
fn resolve_ipv6(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let (addr, zone) = match host.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (host, None),
    };

    let ip: Ipv6Addr = addr.parse().context("invalid IPv6 address")?;
    let scope_id = match zone {
        Some(zone) => zone_to_scope_id(zone)?,
        None => 0,
    };

    Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))
}

/// Converts a zone ID, either an interface name or a number, to a scope ID.
fn zone_to_scope_id(zone: &str) -> anyhow::Result<u32> {
    if let Ok(id) = zone.parse() {
        return Ok(id);
    }
    interface_index(zone).with_context(|| format!("unknown interface: {zone}"))
}

#[cfg(unix)]
fn interface_index(name: &str) -> Option<u32> {
    extern "C" {
        fn if_nametoindex(name: *const std::ffi::c_char) -> std::ffi::c_uint;
    }
    let name = std::ffi::CString::new(name).ok()?;
    match unsafe { if_nametoindex(name.as_ptr()) } {
        0 => None,
        index => Some(index),
    }
}

#[cfg(not(unix))]
fn interface_index(_name: &str) -> Option<u32> {
    None
}

/// Returns the wildcard local address for the given address family.
pub fn unspecified_for(addr: &SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_without_port() {
        assert_eq!(
            resolve_nameserver("8.8.8.8").unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
    }

    #[test]
    fn ipv4_with_port() {
        assert_eq!(
            resolve_nameserver("8.8.8.8:5353").unwrap(),
            "8.8.8.8:5353".parse().unwrap()
        );
    }

    #[test]
    fn ipv6_without_port() {
        assert_eq!(
            resolve_nameserver("2001:4860:4860::8888").unwrap(),
            "[2001:4860:4860::8888]:53".parse().unwrap()
        );
    }

    #[test]
    fn ipv6_with_port() {
        assert_eq!(
            resolve_nameserver("[2001:4860:4860::8888]:5353").unwrap(),
            "[2001:4860:4860::8888]:5353".parse().unwrap()
        );
    }

    #[test]
    fn ipv6_with_numeric_zone() {
        let SocketAddr::V6(addr) = resolve_nameserver("fe80::1%4").unwrap() else {
            panic!("expected IPv6");
        };
        assert_eq!(addr.scope_id(), 4);
        assert_eq!(addr.port(), 53);
    }

    #[test]
    fn ipv6_with_unknown_zone() {
        assert!(resolve_nameserver("fe80::1%nonexistent0").is_err());
    }

    #[test]
    fn invalid_port() {
        assert!(resolve_nameserver("8.8.8.8:abc").is_err());
    }
}
