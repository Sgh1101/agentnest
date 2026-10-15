//! `ServerIdentity`: the PC's TLS identity (docs/security.md 3).
//!
//! * One **P-256 key pair** (rcgen 0.14, ring) is generated on first start and **reused forever**; it is stored through
//!   a [`KeyStore`] (a user-only file in Phase 1, [`keywrap`]).
//! * The self-signed **certificate** (SAN = every non-loopback IP, `not_before = now - 1h`, `not_after = now + 2y`) is
//!   re-issued **with the same key** when the address set changes or less than 30 days remain. The SPKI pin
//!   (`sha256/<base64>` via [`agentnest_protocol::qr::spki_pin`]) is a key fingerprint, so a re-issue never invalidates
//!   a paired phone.
//! * The pin and `pc_id` are derived with the protocol crate helpers so that they are byte-identical to the vectors the
//!   Android side checks.
//!
//! The rustls `ring` provider is installed once ([`install_crypto_provider`]); the workspace has a single crypto backend.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};

use chrono::{DateTime, Duration, Utc};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::redact::TlsKeyPem;
use agentnest_protocol::qr::{pc_id_from_spki, spki_pin};

pub mod keywrap;

pub use keywrap::{AclFileKeyStore, FilePermissions, KeyStore, PlatformPermissions};

/// Re-issue the certificate when fewer days than this remain.
pub const CERT_RENEW_BEFORE_DAYS: i64 = 30;
/// Certificate lifetime.
pub const CERT_LIFETIME_DAYS: i64 = 730;
/// Clock-skew allowance for `not_before`.
pub const CERT_BACKDATE_HOURS: i64 = 1;

/// Errors of the identity module.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// File system or key store failure.
    #[error("identity io error: {0}")]
    Io(#[from] std::io::Error),
    /// Key or certificate generation failed.
    #[error("certificate error: {0}")]
    Cert(String),
    /// The stored key or certificate could not be parsed.
    #[error("stored identity is unreadable: {0}")]
    Corrupt(String),
    /// TLS configuration failed.
    #[error("tls configuration error: {0}")]
    Tls(String),
}

impl From<rcgen::Error> for IdentityError {
    fn from(e: rcgen::Error) -> Self {
        IdentityError::Cert(e.to_string())
    }
}

/// Installs the rustls `ring` crypto provider as the process default, once. Safe to call repeatedly.
pub fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // An error means another provider was installed first; every config in this crate names ring explicitly.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// What [`IdentityStore::load_or_create`] and friends did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityChange {
    /// A new key pair and certificate were generated.
    Created,
    /// The stored key and certificate were used as they are.
    Loaded,
    /// The key was kept, the certificate was re-issued (address change, near expiry or a missing/mismatching file).
    CertReissued,
    /// A new key pair was generated ("regenerate PC identity": every phone has to be paired again).
    Regenerated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CertMeta {
    sans: Vec<String>,
    not_before: String,
    not_after: String,
    issued_at: String,
}

/// The PC's TLS identity. Cheap to clone (the key text is a redacting newtype).
#[derive(Clone)]
pub struct ServerIdentity {
    key_pem: TlsKeyPem,
    cert_der: Vec<u8>,
    cert_pem: String,
    spki_der: Vec<u8>,
    sans: Vec<String>,
    not_after: DateTime<Utc>,
    issued_at: DateTime<Utc>,
}

impl std::fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("pc_id", &self.pc_id())
            .field("sans", &self.sans)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl ServerIdentity {
    /// `pc_` + the first 8 bytes of SHA-256(SPKI) as hex.
    pub fn pc_id(&self) -> String {
        pc_id_from_spki(&self.spki_der)
    }

    /// `sha256/<base64(SHA-256(SPKI))>`: the pin in the QR code.
    pub fn spki_pin(&self) -> String {
        spki_pin(&self.spki_der)
    }

    /// DER `SubjectPublicKeyInfo` of the server key.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The certificate in DER form.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The certificate in PEM form (public information; also stored in `pc_identity.cert_pem`).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The addresses the certificate was issued for.
    pub fn sans(&self) -> &[String] {
        &self.sans
    }

    /// End of the certificate validity.
    pub fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }

    /// When the current certificate was issued.
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// The rustls server configuration: this certificate and key, no client authentication, TLS 1.3 preferred with
    /// TLS 1.2 allowed, ALPN `http/1.1` (WebSocket upgrade), ring provider.
    pub fn rustls_server_config(&self) -> Result<Arc<rustls::ServerConfig>, IdentityError> {
        install_crypto_provider();
        let key_pair = KeyPair::from_pem(self.key_pem.expose())?;
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| IdentityError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(self.cert_der.clone())], key)
            .map_err(|e| IdentityError::Tls(e.to_string()))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

/// Loads, creates and renews the identity files below an `identity` directory.
pub struct IdentityStore {
    dir: PathBuf,
    keys: Box<dyn KeyStore>,
    perms: Box<dyn FilePermissions>,
}

fn sorted_san_strings(addrs: &[IpAddr]) -> Vec<String> {
    let mut v: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
    v.sort();
    v.dedup();
    v
}

fn to_odt(dt: DateTime<Utc>) -> Result<time::OffsetDateTime, IdentityError> {
    time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
        .map_err(|e| IdentityError::Cert(e.to_string()))
}

fn issue_cert(
    key_pair: &KeyPair,
    sans: &[String],
    now: DateTime<Utc>,
) -> Result<(Vec<u8>, String, DateTime<Utc>), IdentityError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.subject_alt_names = sans
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(SanType::IpAddress)
        .collect();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "AgentNest PC");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let not_before = now - Duration::hours(CERT_BACKDATE_HOURS);
    let not_after = now + Duration::days(CERT_LIFETIME_DAYS);
    params.not_before = to_odt(not_before)?;
    params.not_after = to_odt(not_after)?;
    let cert = params.self_signed(key_pair)?;
    Ok((cert.der().to_vec(), cert.pem(), not_after))
}

impl IdentityStore {
    /// An identity store below `dir` with the Phase 1 user-only key file.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let keys = Box::new(AclFileKeyStore::new(dir.join("server-key.pem")));
        Self {
            dir,
            keys,
            perms: Box::new(PlatformPermissions),
        }
    }

    /// An identity store with explicit key storage (tests, future DPAPI store).
    pub fn with_parts(
        dir: impl Into<PathBuf>,
        keys: Box<dyn KeyStore>,
        perms: Box<dyn FilePermissions>,
    ) -> Self {
        Self {
            dir: dir.into(),
            keys,
            perms,
        }
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join("server-cert.pem")
    }

    fn meta_path(&self) -> PathBuf {
        self.dir.join("cert-meta.json")
    }

    fn write_cert_files(&self, cert_pem: &str, meta: &CertMeta) -> Result<(), IdentityError> {
        std::fs::create_dir_all(&self.dir)?;
        // The certificate is public, but it is written through the same helper to keep one write path.
        keywrap::write_user_only(&self.cert_path(), cert_pem.as_bytes(), self.perms.as_ref())?;
        let json =
            serde_json::to_vec_pretty(meta).map_err(|e| IdentityError::Corrupt(e.to_string()))?;
        keywrap::write_user_only(&self.meta_path(), &json, self.perms.as_ref())?;
        Ok(())
    }

    fn build(
        key_pem: TlsKeyPem,
        key_pair: &KeyPair,
        cert_der: Vec<u8>,
        cert_pem: String,
        meta: &CertMeta,
        not_after: DateTime<Utc>,
        issued_at: DateTime<Utc>,
    ) -> ServerIdentity {
        ServerIdentity {
            key_pem,
            cert_der,
            cert_pem,
            spki_der: key_pair.subject_public_key_info(),
            sans: meta.sans.clone(),
            not_after,
            issued_at,
        }
    }

    fn create_with_key(
        &self,
        key_pem: TlsKeyPem,
        key_pair: &KeyPair,
        sans: &[IpAddr],
        now: DateTime<Utc>,
    ) -> Result<ServerIdentity, IdentityError> {
        let sans = sorted_san_strings(sans);
        let (cert_der, cert_pem, not_after) = issue_cert(key_pair, &sans, now)?;
        let meta = CertMeta {
            sans,
            not_before: (now - Duration::hours(CERT_BACKDATE_HOURS)).to_rfc3339(),
            not_after: not_after.to_rfc3339(),
            issued_at: now.to_rfc3339(),
        };
        self.write_cert_files(&cert_pem, &meta)?;
        Ok(Self::build(
            key_pem, key_pair, cert_der, cert_pem, &meta, not_after, now,
        ))
    }

    fn generate_key(&self) -> Result<(TlsKeyPem, KeyPair), IdentityError> {
        // `KeyPair::generate()` is P-256 / SHA-256 ECDSA on the ring backend.
        let key_pair = KeyPair::generate()?;
        let pem = TlsKeyPem::new(key_pair.serialize_pem());
        self.keys.store(&pem)?;
        Ok((pem, key_pair))
    }

    /// Loads the identity, creating key and certificate on first start and re-issuing the certificate (same key)
    /// when `sans` changed, less than [`CERT_RENEW_BEFORE_DAYS`] remain, or the certificate does not belong to the
    /// key.
    pub fn load_or_create(
        &self,
        sans: &[IpAddr],
        now: DateTime<Utc>,
    ) -> Result<(ServerIdentity, IdentityChange), IdentityError> {
        let Some(key_pem) = self.keys.load()? else {
            let (pem, pair) = self.generate_key()?;
            return Ok((
                self.create_with_key(pem, &pair, sans, now)?,
                IdentityChange::Created,
            ));
        };
        let key_pair = KeyPair::from_pem(key_pem.expose())
            .map_err(|e| IdentityError::Corrupt(format!("server key: {e}")))?;
        let want = sorted_san_strings(sans);
        let loaded = (|| -> Option<(ServerIdentity, bool)> {
            let cert_pem = std::fs::read_to_string(self.cert_path()).ok()?;
            let meta: CertMeta =
                serde_json::from_slice(&std::fs::read(self.meta_path()).ok()?).ok()?;
            let der = pem_to_der(&cert_pem)?;
            let spki = spki_from_cert_der(&der)?;
            let not_after = DateTime::parse_from_rfc3339(&meta.not_after)
                .ok()?
                .with_timezone(&Utc);
            let issued_at = DateTime::parse_from_rfc3339(&meta.issued_at)
                .ok()?
                .with_timezone(&Utc);
            let belongs = spki == key_pair.subject_public_key_info();
            let fresh = not_after - now > Duration::days(CERT_RENEW_BEFORE_DAYS);
            let same_addrs = meta.sans == want;
            let identity = Self::build(
                key_pem.clone(),
                &key_pair,
                der,
                cert_pem,
                &meta,
                not_after,
                issued_at,
            );
            Some((identity, belongs && fresh && same_addrs))
        })();
        match loaded {
            Some((identity, true)) => Ok((identity, IdentityChange::Loaded)),
            _ => Ok((
                self.create_with_key(key_pem, &key_pair, sans, now)?,
                IdentityChange::CertReissued,
            )),
        }
    }

    /// Re-issues the certificate with the **same key** if `sans` changed or the certificate is near expiry. Returns the
    /// new identity, or `None` if nothing had to change.
    pub fn refresh(
        &self,
        current: &ServerIdentity,
        sans: &[IpAddr],
        now: DateTime<Utc>,
    ) -> Result<Option<ServerIdentity>, IdentityError> {
        let want = sorted_san_strings(sans);
        let near_expiry = current.not_after - now <= Duration::days(CERT_RENEW_BEFORE_DAYS);
        if want == current.sans && !near_expiry {
            return Ok(None);
        }
        let key_pair = KeyPair::from_pem(current.key_pem.expose())?;
        Ok(Some(self.create_with_key(
            current.key_pem.clone(),
            &key_pair,
            sans,
            now,
        )?))
    }

    /// "Regenerate PC identity" (security.md 10): a new key pair, hence a new pin. Every phone must pair again.
    pub fn regenerate(
        &self,
        sans: &[IpAddr],
        now: DateTime<Utc>,
    ) -> Result<ServerIdentity, IdentityError> {
        self.keys.delete()?;
        let (pem, pair) = self.generate_key()?;
        self.create_with_key(pem, &pair, sans, now)
    }

    /// The identity directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// The current LAN addresses worth advertising and binding to, best first (see [`select_lan_addresses`]).
///
/// The preferred address is the one the operating system would use to reach the outside world (the interface that
/// holds the default route), found without sending a packet: a UDP socket "connected" to a documentation address only
/// asks the routing table for the source address.
pub fn lan_addresses() -> Vec<IpAddr> {
    let ifaces = local_ip_address::list_afinet_netifas().unwrap_or_default();
    select_lan_addresses(&ifaces, default_route_source())
}

/// The local address the routing table picks for an outside destination, `None` without a default route. No packet
/// is sent (a UDP `connect` only selects the route).
fn default_route_source() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // TEST-NET-3 (RFC 5737): never routed anywhere, only used to ask for the route
    socket.connect(("203.0.113.1", 9)).ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// `true` for an address that may be advertised to a phone: **private** space only - RFC 1918 IPv4 (`10/8`,
/// `172.16/12`, `192.168/16`) and IPv6 unique-local (`fc00::/7`). Loopback, unspecified, multicast, link-local
/// (a phone cannot choose the zone), CGNAT (`100.64/10`, typically a VPN) and public addresses are not.
pub fn is_usable_lan_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// An interface that looks virtual (container bridges, WSL / Hyper-V switches, VM host-only adapters, VPN tunnels). Such
/// an address is still advertised, but **after** the physical ones: the PC's `link.bind_addr` default is the first
/// entry, and a phone cannot reach a WSL or Docker address anyway. This is a name heuristic and deliberately only
/// reorders, it never hides an address.
fn looks_virtual(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const PREFIXES: [&str; 14] = [
        "veth", "docker", "br-", "virbr", "vboxnet", "vmnet", "lxc", "podman", "cni", "flannel",
        "tun", "tap", "utun", "wg",
    ];
    const CONTAINS: [&str; 8] = [
        "wsl",
        "vethernet",
        "hyper-v",
        "vmware",
        "virtualbox",
        "tailscale",
        "zerotier",
        "loopback",
    ];
    PREFIXES.iter().any(|p| n.starts_with(p)) || CONTAINS.iter().any(|c| n.contains(c))
}

/// Picks and orders the addresses of `ifaces` (`(interface name, address)`): only [`is_usable_lan_address`] ones, the
/// address of the default-route interface (`default_route`) first, then the addresses of physical-looking interfaces
/// before virtual ones, IPv4 before IPv6, each group sorted **numerically** (`10.0.0.9` before `10.0.0.10`).
/// Duplicates are removed.
pub fn select_lan_addresses(
    ifaces: &[(String, IpAddr)],
    default_route: Option<IpAddr>,
) -> Vec<IpAddr> {
    let mut v: Vec<(bool, bool, bool, IpAddr)> = ifaces
        .iter()
        .filter(|(_, ip)| is_usable_lan_address(*ip))
        .map(|(name, ip)| {
            (
                Some(*ip) != default_route, // the default route's address first (false sorts first)
                looks_virtual(name),
                ip.is_ipv6(),
                *ip,
            )
        })
        .collect();
    v.sort();
    let mut out: Vec<IpAddr> = Vec::new();
    for (_, _, _, ip) in v {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------------
// Minimal DER helpers (no x509 parser dependency): PEM -> DER and the SubjectPublicKeyInfo of a certificate.
// ---------------------------------------------------------------------------------------------------------------------

/// Decodes the first `CERTIFICATE` block of a PEM text.
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem.find(begin)? + begin.len();
    let stop = pem[start..].find(end)? + start;
    let body: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD.decode(body).ok()
}

/// Reads one DER TLV at the start of `buf`: `(tag, header_len, content_len)`.
fn der_header(buf: &[u8]) -> Option<(u8, usize, usize)> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    if first < 0x80 {
        return Some((tag, 2, usize::from(first)));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | usize::from(*buf.get(2 + i)?);
    }
    Some((tag, 2 + n, len))
}

/// The DER `SubjectPublicKeyInfo` of an X.509 certificate (the exact bytes of the SPKI TLV).
pub fn spki_from_cert_der(cert: &[u8]) -> Option<Vec<u8>> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version?, serial, sigAlg, issuer, validity, subject, spki, ... } ... }
    let (tag, hl, cl) = der_header(cert)?;
    if tag != 0x30 || hl + cl > cert.len() {
        return None;
    }
    let tbs_all = &cert[hl..hl + cl];
    let (tag, hl, cl) = der_header(tbs_all)?;
    if tag != 0x30 || hl + cl > tbs_all.len() {
        return None;
    }
    let mut rest = &tbs_all[hl..hl + cl];
    // optional explicit version [0]
    let (tag, h, c) = der_header(rest)?;
    if tag == 0xa0 {
        rest = rest.get(h + c..)?;
    }
    // serial, signature, issuer, validity, subject
    for _ in 0..5 {
        let (_, h, c) = der_header(rest)?;
        rest = rest.get(h + c..)?;
    }
    let (tag, h, c) = der_header(rest)?;
    if tag != 0x30 {
        return None;
    }
    rest.get(..h + c).map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentnest_protocol::canonical::sha256;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-15T09:12:33Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn first_start_creates_key_and_cert_and_the_pin_matches_the_protocol_helpers() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        let (id, change) = store
            .load_or_create(&ips(&["192.168.0.10", "10.8.0.2"]), now())
            .unwrap();
        assert_eq!(change, IdentityChange::Created);
        // the SPKI of the certificate is the SPKI of the key; the pin is the OkHttp sha256/ format
        assert_eq!(spki_from_cert_der(id.cert_der()).unwrap(), id.spki_der());
        let pin = id.spki_pin();
        let b64 = pin.strip_prefix("sha256/").unwrap();
        assert_eq!(b64.len(), 44);
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap(),
            sha256(id.spki_der()).to_vec()
        );
        assert!(id.pc_id().starts_with("pc_"));
        assert_eq!(id.pc_id().len(), 3 + 16);
        assert_eq!(id.sans(), ["10.8.0.2", "192.168.0.10"]);
        // lifetime: ~2 years
        assert!(id.not_after() - now() > Duration::days(700));
        let cfg = id.rustls_server_config().unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn restart_loads_the_same_identity_without_reissuing() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        let sans = ips(&["192.168.0.10"]);
        let (a, _) = store.load_or_create(&sans, now()).unwrap();
        let (b, change) = store
            .load_or_create(&sans, now() + Duration::days(1))
            .unwrap();
        assert_eq!(change, IdentityChange::Loaded);
        assert_eq!(a.spki_pin(), b.spki_pin());
        assert_eq!(a.cert_der(), b.cert_der());
    }

    #[test]
    fn an_address_change_reissues_the_certificate_with_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        let (a, _) = store
            .load_or_create(&ips(&["192.168.0.10"]), now())
            .unwrap();
        // via load_or_create (restart on another network)
        let (b, change) = store
            .load_or_create(&ips(&["192.168.0.10", "172.16.1.5"]), now())
            .unwrap();
        assert_eq!(change, IdentityChange::CertReissued);
        assert_eq!(a.spki_pin(), b.spki_pin(), "the pin must not change");
        assert_ne!(a.cert_der(), b.cert_der());
        assert_eq!(b.sans(), ["172.16.1.5", "192.168.0.10"]);
        // via refresh (running daemon sees the address change)
        let c = store
            .refresh(&b, &ips(&["10.0.0.7"]), now())
            .unwrap()
            .expect("sans changed");
        assert_eq!(c.spki_pin(), a.spki_pin());
        assert_eq!(c.sans(), ["10.0.0.7"]);
        assert!(store
            .refresh(&c, &ips(&["10.0.0.7"]), now())
            .unwrap()
            .is_none());
    }

    #[test]
    fn near_expiry_reissues_with_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        let sans = ips(&["192.168.0.10"]);
        let (a, _) = store.load_or_create(&sans, now()).unwrap();
        let later = now() + Duration::days(CERT_LIFETIME_DAYS - 29);
        let b = store.refresh(&a, &sans, later).unwrap().expect("renew");
        assert_eq!(a.spki_pin(), b.spki_pin());
        assert!(b.not_after() > a.not_after());
        let (c, change) = store
            .load_or_create(&sans, later + Duration::days(1))
            .unwrap();
        assert_eq!(change, IdentityChange::Loaded, "the renewed cert is fresh");
        assert_eq!(c.spki_pin(), a.spki_pin());
        // 31 days before expiry is not yet renewed
        let earlier = now() + Duration::days(CERT_LIFETIME_DAYS - 31);
        assert!(store.refresh(&a, &sans, earlier).unwrap().is_none());
    }

    #[test]
    fn a_missing_or_foreign_certificate_is_reissued_for_the_stored_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        let sans = ips(&["192.168.0.10"]);
        let (a, _) = store.load_or_create(&sans, now()).unwrap();
        std::fs::remove_file(store.cert_path()).unwrap();
        let (b, change) = store.load_or_create(&sans, now()).unwrap();
        assert_eq!(change, IdentityChange::CertReissued);
        assert_eq!(a.spki_pin(), b.spki_pin());
    }

    #[test]
    fn regenerate_changes_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        let sans = ips(&["192.168.0.10"]);
        let (a, _) = store.load_or_create(&sans, now()).unwrap();
        let b = store.regenerate(&sans, now()).unwrap();
        assert_ne!(a.spki_pin(), b.spki_pin());
        let (c, change) = store.load_or_create(&sans, now()).unwrap();
        assert_eq!(change, IdentityChange::Loaded);
        assert_eq!(c.spki_pin(), b.spki_pin());
    }

    #[test]
    fn a_corrupt_key_file_is_an_error_not_a_silent_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        std::fs::create_dir_all(store.dir()).unwrap();
        std::fs::write(store.dir().join("server-key.pem"), "garbage").unwrap();
        assert!(matches!(
            store.load_or_create(&ips(&["192.168.0.10"]), now()),
            Err(IdentityError::Corrupt(_))
        ));
    }

    #[test]
    fn usable_lan_addresses_are_private_space_only() {
        for ok in [
            "192.168.0.10",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "fd00::5",
            "fc00::1",
        ] {
            assert!(is_usable_lan_address(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "100.64.0.1",
            "8.8.8.8",
            "172.32.0.1",
            "172.15.0.1",
            "fe80::1",
            "::1",
            "::",
            "ff02::1",
            "2001:4860:4860::8888",
        ] {
            assert!(!is_usable_lan_address(bad.parse().unwrap()), "{bad}");
        }
        for ip in lan_addresses() {
            assert!(is_usable_lan_address(ip));
        }
    }

    fn nic(name: &str, ip: &str) -> (String, IpAddr) {
        (name.to_owned(), ip.parse().unwrap())
    }

    /// Review finding: addresses were sorted as strings (`10.0.0.10` before `10.0.0.9`), any non-loopback address
    /// (public, CGNAT) was accepted and the first entry - the default bind address - was arbitrary.
    #[test]
    fn lan_address_selection_is_numeric_private_only_and_prefers_the_default_route() {
        let ifaces = vec![
            nic("vEthernet (WSL)", "172.28.0.1"),
            nic("Ethernet", "192.168.0.10"),
            nic("Ethernet", "10.0.0.10"),
            nic("Ethernet", "10.0.0.9"),
            nic("Wi-Fi", "192.168.1.5"),
            nic("Wi-Fi", "fd12:3456::7"),
            nic("Wi-Fi", "fe80::1"),
            nic("Tailscale", "100.101.102.103"),
            nic("Ethernet 2", "203.0.113.7"),
            nic("lo", "127.0.0.1"),
            nic("docker0", "172.17.0.1"),
            nic("Ethernet", "192.168.0.10"), // duplicate
        ];
        // without a default route: physical before virtual, IPv4 before IPv6, numeric order inside a group
        assert_eq!(
            select_lan_addresses(&ifaces, None),
            ips(&[
                "10.0.0.9",
                "10.0.0.10",
                "192.168.0.10",
                "192.168.1.5",
                "fd12:3456::7",
                "172.17.0.1",
                "172.28.0.1"
            ])
        );
        // the default route's address comes first whatever its number is
        assert_eq!(
            select_lan_addresses(&ifaces, Some("192.168.1.5".parse().unwrap()))[0],
            "192.168.1.5".parse::<IpAddr>().unwrap()
        );
        // even when it is on a "virtual looking" interface name the OS chose it: it wins
        assert_eq!(
            select_lan_addresses(&ifaces, Some("172.28.0.1".parse().unwrap()))[0],
            "172.28.0.1".parse::<IpAddr>().unwrap()
        );
        assert!(select_lan_addresses(&[], None).is_empty());
        assert!(!looks_virtual("Ethernet") && !looks_virtual("Wi-Fi") && !looks_virtual("eth0"));
        assert!(
            looks_virtual("vEthernet (WSL)") && looks_virtual("docker0") && looks_virtual("tun0")
        );
    }

    #[test]
    fn der_helpers_reject_garbage() {
        assert!(spki_from_cert_der(&[]).is_none());
        assert!(spki_from_cert_der(&[0x30, 0x03, 0x01, 0x02, 0x03]).is_none());
        assert!(pem_to_der("not a pem").is_none());
    }

    #[test]
    fn the_private_key_text_never_reaches_debug_output() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        let (a, _) = store
            .load_or_create(&ips(&["192.168.0.10"]), now())
            .unwrap();
        let shown = format!("{a:?}");
        assert!(!shown.contains("PRIVATE"));
        assert!(!shown.contains("BEGIN"));
    }
}
