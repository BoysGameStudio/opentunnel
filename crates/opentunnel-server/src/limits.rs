//! Limits on the work anyone on the Internet can make the server do on the shared ACME account and DNS zone:
//! tunnels created per client address, new certificates per tunnel, and no new issuance while too much is
//! queued. Rates are kept in the database (`rate_limits`), so they hold across every machine.
//!
//! Rates use GCRA: a key stores the time its budget is next back to full ("theoretical arrival time"). A request
//! is allowed when that is at most `tolerance` ahead of now, and pushes it `interval` further, so `burst`
//! requests go through at once and one more every `interval` after.

use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use hyper::header::HeaderMap;
use tracing::debug;

use crate::clock::{Clock, DAY_MS, HOUR_MS};
use crate::store::Store;

/// Cloudflare's published ranges (<https://www.cloudflare.com/ips-v4>, <https://www.cloudflare.com/ips-v6>,
/// October 2026): the only sources whose `CF-Connecting-IP` is believed by default.
pub const CLOUDFLARE_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

const CLIENT_HEADER: &str = "cf-connecting-ip";
/// How long the pending job count is reused before it is read again.
const BACKLOG_TTL_MS: u64 = 5_000;
/// What a 503 for a full queue asks clients to wait.
pub const BACKLOG_RETRY_MS: u64 = 30_000;

/// IPv4-mapped IPv6 addresses as IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value, None),
        };
        let network: IpAddr = address
            .parse()
            .with_context(|| format!("{value} is not a CIDR"))?;
        let network = canonical(network);
        let bits = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .with_context(|| format!("{value} is not a CIDR"))?,
            None => bits,
        };
        if prefix > bits {
            bail!("{value} is not a CIDR");
        }
        Ok(Self { network, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, canonical(ip)) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// The proxies whose client header is believed.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// `TRUSTED_PROXY_RANGES`: Cloudflare's ranges when empty, none for `off`.
    pub fn parse(ranges: &[String]) -> Result<Self> {
        let ranges: Vec<&str> = ranges
            .iter()
            .map(|range| range.trim())
            .filter(|range| !range.is_empty())
            .collect();
        match ranges.as_slice() {
            [] => Self::parse_all(CLOUDFLARE_RANGES),
            ["off"] => Ok(Self::default()),
            ranges => Self::parse_all(ranges),
        }
    }

    fn parse_all(ranges: &[&str]) -> Result<Self> {
        ranges
            .iter()
            .map(|range| Cidr::parse(range))
            .collect::<Result<_>>()
            .map(Self)
            .context("TRUSTED_PROXY_RANGES")
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|cidr| cidr.contains(ip))
    }

    /// The client behind a request from `source`: the `CF-Connecting-IP` header when `source` is a trusted proxy
    /// and the header is one address, otherwise `source` itself, whatever the headers say.
    pub fn client(&self, source: IpAddr, headers: &HeaderMap) -> IpAddr {
        let source = canonical(source);
        if !self.contains(source) {
            return source;
        }
        headers
            .get(CLIENT_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .map_or(source, canonical)
    }
}

/// The key a client address is counted under: the address for IPv4, its /64 for IPv6 (one subscriber's prefix).
pub fn client_key(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let network = u128::from(v6) & (u128::MAX << 64);
            format!("{}/64", std::net::Ipv6Addr::from(network))
        }
    }
}

/// `count` per `period_ms` on average, `burst` at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    pub interval_ms: u64,
    pub tolerance_ms: u64,
}

impl Rate {
    /// `None` (no limit) when `count` is 0.
    pub fn new(count: u32, period_ms: u64, burst: u32) -> Option<Self> {
        let interval_ms = period_ms.checked_div(u64::from(count))?.max(1);
        Some(Self {
            interval_ms,
            tolerance_ms: interval_ms * u64::from(burst.max(1) - 1),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Limited { retry_after_ms: u64 },
}

pub struct Limits {
    store: Store,
    clock: Clock,
    pub proxies: TrustedProxies,
    create: Option<Rate>,
    issuance: Option<Rate>,
    backlog_limit: u64,
    /// The pending job count and when it was read.
    backlog: Mutex<Option<(u64, u64)>>,
}

impl Limits {
    pub fn new(
        store: Store,
        clock: Clock,
        proxies: TrustedProxies,
        create: Option<Rate>,
        issuance: Option<Rate>,
        backlog_limit: u64,
    ) -> Self {
        Self {
            store,
            clock,
            proxies,
            create,
            issuance,
            backlog_limit,
            backlog: Mutex::new(None),
        }
    }

    pub fn from_config(config: &crate::config::Config, store: Store, clock: Clock) -> Result<Self> {
        Ok(Self::new(
            store,
            clock,
            TrustedProxies::parse(&config.trusted_proxy_ranges)?,
            Rate::new(
                config.create_rate_per_hour,
                HOUR_MS,
                config.create_rate_burst,
            ),
            Rate::new(
                config.issuance_rate_per_day,
                DAY_MS,
                config.issuance_rate_burst,
            ),
            config.issuance_backlog_limit,
        ))
    }

    async fn take(&self, rate: Option<Rate>, key: String, limit: &'static str) -> Result<Verdict> {
        let Some(rate) = rate else {
            return Ok(Verdict::Allowed);
        };
        let now = self.clock.now_ms();
        let verdict = self.store.take_rate(&key, now, rate).await?;
        if let Verdict::Limited { retry_after_ms } = verdict {
            crate::metrics::limited(limit);
            debug!(limit, retry_after_ms, "rate limited");
        }
        Ok(verdict)
    }

    /// One tunnel created by `client`.
    pub async fn create(&self, client: IpAddr) -> Result<Verdict> {
        self.take(
            self.create,
            format!("create:{}", client_key(client)),
            "create_rate",
        )
        .await
    }

    /// One new certificate for `tunnel`.
    pub async fn issuance(&self, tunnel: &str) -> Result<Verdict> {
        self.take(self.issuance, format!("issue:{tunnel}"), "issuance_rate")
            .await
    }

    /// Whether more certificate jobs are pending than new issuance may add to, cluster-wide. When the count
    /// cannot be read, issuance goes ahead (whatever needs the database then fails on its own).
    pub async fn backlogged(&self) -> bool {
        if self.backlog_limit == 0 {
            return false;
        }
        let now = self.clock.now_ms();
        let cached = *self.backlog.lock().expect("backlog lock");
        let pending = match cached {
            Some((pending, at)) if now.saturating_sub(at) < BACKLOG_TTL_MS => pending,
            _ => match self.store.pending_jobs().await {
                Ok(pending) => {
                    *self.backlog.lock().expect("backlog lock") = Some((pending, now));
                    pending
                }
                Err(error) => {
                    debug!(%error, "reading the certificate job backlog failed");
                    return false;
                }
            },
        };
        let backlogged = pending > self.backlog_limit;
        if backlogged {
            crate::metrics::limited("issuance_backlog");
        }
        backlogged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn headers(client: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_HEADER, HeaderValue::from_str(client).unwrap());
        headers
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn believes_the_client_header_only_from_cloudflare() {
        let proxies = TrustedProxies::parse(&[]).unwrap();
        // Cloudflare edges, IPv4, IPv6 and IPv4-mapped.
        for edge in [
            "172.68.1.2",
            "162.158.255.1",
            "104.16.0.1",
            "2606:4700:10::1",
            "2a06:98c7:ffff::1",
            "::ffff:172.68.1.2",
        ] {
            assert!(proxies.contains(ip(edge)), "{edge}");
            assert_eq!(
                proxies.client(ip(edge), &headers("203.0.113.9")),
                ip("203.0.113.9")
            );
            assert_eq!(
                proxies.client(ip(edge), &headers("2001:db8::1")),
                ip("2001:db8::1")
            );
            // No header, or one that is not an address: the edge itself.
            assert_eq!(
                proxies.client(ip(edge), &HeaderMap::new()),
                canonical(ip(edge))
            );
            assert_eq!(
                proxies.client(ip(edge), &headers("203.0.113.9, 10.0.0.1")),
                canonical(ip(edge))
            );
        }
        // Anyone else's header is ignored: a spoofed CF-Connecting-IP counts against the sender.
        for source in [
            "203.0.113.50",
            "172.63.255.255",
            "172.72.0.0",
            "104.32.0.1",
            "2606:4701::1",
            "fdaa::1",
            "127.0.0.1",
        ] {
            assert!(!proxies.contains(ip(source)), "{source}");
            assert_eq!(
                proxies.client(ip(source), &headers("198.51.100.1")),
                ip(source)
            );
        }
        let none = TrustedProxies::parse(&["off".into()]).unwrap();
        assert_eq!(
            none.client(ip("172.68.1.2"), &headers("203.0.113.9")),
            ip("172.68.1.2")
        );
        let custom = TrustedProxies::parse(&["10.0.0.0/8".into(), " fd00::/8".into()]).unwrap();
        assert_eq!(
            custom.client(ip("10.1.2.3"), &headers("203.0.113.9")),
            ip("203.0.113.9")
        );
        assert_eq!(
            custom.client(ip("fd12::1"), &headers("203.0.113.9")),
            ip("203.0.113.9")
        );
        assert_eq!(
            custom.client(ip("172.68.1.2"), &headers("203.0.113.9")),
            ip("172.68.1.2")
        );
        assert!(TrustedProxies::parse(&["10.0.0.0/33".into()]).is_err());
        assert!(TrustedProxies::parse(&["nonsense".into()]).is_err());
        let all = TrustedProxies::parse(&["0.0.0.0/0".into()]).unwrap();
        assert!(all.contains(ip("1.2.3.4")));
    }

    #[test]
    fn counts_ipv6_clients_by_their_64() {
        assert_eq!(client_key(ip("203.0.113.9")), "203.0.113.9");
        assert_eq!(client_key(ip("::ffff:203.0.113.9")), "203.0.113.9");
        assert_eq!(
            client_key(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            "2001:db8:1:2::/64"
        );
        assert_eq!(
            client_key(ip("2001:db8:1:2::1")),
            client_key(ip("2001:db8:1:2:ffff::"))
        );
        assert_ne!(
            client_key(ip("2001:db8:1:2::1")),
            client_key(ip("2001:db8:1:3::1"))
        );
    }

    #[test]
    fn rates_spread_the_count_over_the_period() {
        assert_eq!(
            Rate::new(30, HOUR_MS, 10),
            Some(Rate {
                interval_ms: 120_000,
                tolerance_ms: 1_080_000
            })
        );
        assert_eq!(Rate::new(5, DAY_MS, 1).unwrap().tolerance_ms, 0);
        assert_eq!(Rate::new(0, DAY_MS, 5), None);
    }
}
