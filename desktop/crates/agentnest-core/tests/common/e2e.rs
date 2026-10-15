//! End-to-end harness: a real daemon on ephemeral ports in a temp dir, a real pinned-TLS WebSocket phone client and
//! blocking HTTP calls against the loopback collector.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentnest_core::config::AppConfig;
use agentnest_core::daemon::{Daemon, DaemonHandle, DaemonOptions};
use agentnest_core::events::{DaemonEvent, PairingUiEvent};
use agentnest_protocol::canonical::{canonical_pair_bytes, pair_proof, sas};
use agentnest_protocol::qr::{b64_decode, b64_encode};
use agentnest_protocol::{
    ApprovalRequest, Decision, DecisionAuth, DecisionPayload, DeviceInfo, ErrorCode, Frame,
    HelloPayload, Message, PairPayload, Secret,
};
use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::Message as WsMsg;
use tokio_tungstenite::WebSocketStream;

pub type Tls = tokio_rustls::client::TlsStream<TcpStream>;

// ---------------------------------------------------------------------------------------------------------------------
// the daemon
// ---------------------------------------------------------------------------------------------------------------------

pub struct E2e {
    pub dm: DaemonHandle,
    pub dir: tempfile::TempDir,
    pub events: broadcast::Receiver<DaemonEvent>,
}

impl E2e {
    pub async fn start() -> Self {
        Self::start_with(|_, _| {}).await
    }

    pub async fn start_with(f: impl FnOnce(&mut DaemonOptions, &mut AppConfig)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self::start_in(dir, f).await
    }

    pub async fn start_in(
        dir: tempfile::TempDir,
        f: impl FnOnce(&mut DaemonOptions, &mut AppConfig),
    ) -> Self {
        let mut options = DaemonOptions::for_dir(dir.path());
        let mut config = AppConfig::load(&options.paths.config).unwrap_or_default();
        f(&mut options, &mut config);
        let dm = Daemon::start_async(config, options)
            .await
            .expect("daemon start");
        let events = dm.subscribe();
        Self { dm, dir, events }
    }

    /// Stops the daemon gracefully and starts a new one on the same directory.
    pub async fn restart(self, f: impl FnOnce(&mut DaemonOptions, &mut AppConfig)) -> Self {
        let E2e { dm, dir, events } = self;
        drop(events);
        let _ = dm.shutdown().await;
        drop(dm);
        tokio::time::sleep(Duration::from_millis(100)).await;
        Self::start_in(dir, f).await
    }

    /// Simulates a crash: the runtime is dropped without any shutdown command.
    pub async fn crash_and_restart(
        self,
        f: impl FnOnce(&mut DaemonOptions, &mut AppConfig),
    ) -> Self {
        let E2e { dm, dir, events } = self;
        drop(events);
        drop(dm);
        tokio::time::sleep(Duration::from_millis(200)).await;
        Self::start_in(dir, f).await
    }

    pub fn token(&self) -> String {
        self.dm.hook_token().expose().to_owned()
    }

    pub fn hook_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.dm.hook_port())
    }

    pub fn link_addr(&self) -> SocketAddr {
        self.dm.link_addr().expect("link listening")
    }

    /// A blocking HTTP call with the valid token on the blocking pool.
    pub async fn hook_post(&self, path: &str, body: Value) -> (u16, String) {
        let url = self.hook_url(path);
        let token = self.token();
        tokio::task::spawn_blocking(move || post_blocking(&url, &token, &body))
            .await
            .unwrap()
    }

    /// Starts a hold (PermissionRequest) in the background; the join handle yields `(status, body)`.
    pub fn hold(&self, body: Value) -> tokio::task::JoinHandle<(u16, String)> {
        let url = self.hook_url("/v1/hooks/claude-code");
        let token = self.token();
        tokio::task::spawn_blocking(move || post_blocking(&url, &token, &body))
    }

    /// A hold whose transport errors are values.
    pub fn hold_result(
        &self,
        body: Value,
    ) -> tokio::task::JoinHandle<Result<(u16, String), String>> {
        let url = self.hook_url("/v1/hooks/claude-code");
        let token = self.token();
        tokio::task::spawn_blocking(move || post_result(&url, &token, &body))
    }

    /// Pairs a new phone through the full flow (R1 accepted, QR, `pair`, SAS check, PC confirmation).
    pub async fn pair(&self, name: &str) -> PairedPhone {
        let mut attempt = self.pair_attempt(name).await;
        let sas = attempt.pending_sas().await;
        assert_eq!(
            sas, attempt.want_sas,
            "the SAS differs between the phone and the PC"
        );
        self.dm
            .pairing_confirm(&attempt.pairing_id, true)
            .await
            .expect("pairing_confirm");
        attempt.finish().await
    }

    /// Starts pairing up to and including the `pair_pending` (SAS) frame.
    pub async fn pair_attempt(&self, name: &str) -> PairAttempt {
        let started = self.begin_qr().await;
        self.pair_with(started, name, Tweak::None).await
    }

    /// R1 accepted + pairing mode on (the QR exists).
    pub async fn begin_qr(&self) -> agentnest_core::auth::pairing::PairingStarted {
        let _ = self.dm.risk_accept().await;
        self.dm.pairing_start().await.expect("pairing_start")
    }

    /// Connects, answers the challenge with a `pair` frame (optionally tampered) and returns the open attempt.
    pub async fn pair_with(
        &self,
        started: agentnest_core::auth::pairing::PairingStarted,
        name: &str,
        tweak: Tweak,
    ) -> PairAttempt {
        let payload = started.payload.clone();
        // Subscribe to the daemon events BEFORE the `pair` frame goes out: the PC modal event (`ConfirmRequested`)
        // is emitted as soon as the daemon has seen the frame, and a receiver created afterwards misses it (that race
        // made `pairing_happy_path_sas_agrees...` flaky).
        let dm_events = self.dm.subscribe();
        let mut ws = Phone::connect(self.link_addr(), &payload.spki_pin)
            .await
            .expect("tls");
        let challenge = ws.expect_challenge().await;
        let secret = payload.pairing_secret_bytes().unwrap();
        let spki = phone_spki();
        let name = name.to_owned();
        let raw = b64_decode(&challenge.challenge_b64).unwrap();
        let bytes = canonical_pair_bytes(&challenge.pc_id, &payload.pairing_id, &raw, &name, &spki)
            .unwrap();
        let mut proof = pair_proof(&secret, &bytes);
        let want_sas = sas(&secret, &raw, &spki).unwrap();
        let mut pairing_id = payload.pairing_id.clone();
        let mut challenge_b64 = challenge.challenge_b64.clone();
        match tweak {
            Tweak::None => {}
            Tweak::WrongProof => proof[0] ^= 0xff,
            Tweak::WrongChallenge => challenge_b64 = b64_encode(&[7u8; 16]),
            Tweak::UnknownPairingId => pairing_id = "p_does_not_exist".to_owned(),
        }
        ws.send(Message::Pair(PairPayload {
            pairing_id,
            challenge_b64,
            device: DeviceInfo {
                name: name.clone(),
                platform: "android".into(),
                model: Some("Pixel".into()),
                os_version: Some("15".into()),
                app_version: Some("0.1.0".into()),
            },
            device_pubkey_spki_b64: Some(b64_encode(&spki)),
            proof_b64: Secret::new(b64_encode(&proof)),
            protocol: 1,
        }))
        .await;
        PairAttempt {
            ws,
            pairing_id: payload.pairing_id.clone(),
            want_sas,
            started: Some(started),
            dm_events,
            pin: payload.spki_pin.clone(),
            addr: self.link_addr(),
            name,
        }
    }

    /// Pairs and consumes the `welcome` + `snapshot` that follow on the pairing connection.
    pub async fn pair_ready(&self, name: &str) -> (PairedPhone, Phone) {
        let mut p = self.pair(name).await;
        let mut ws = p.ws.take().expect("pairing connection");
        let w = ws.recv_type("welcome").await;
        assert!(matches!(w.message, Message::Welcome(_)));
        let snap = ws.recv_type("snapshot").await;
        assert!(matches!(snap.message, Message::Snapshot(_)));
        (p, ws)
    }

    /// A phone connection authenticated with `hello`.
    pub async fn hello(&self, paired: &PairedPhone, last_seq: i64, wants_snapshot: bool) -> Phone {
        let mut ws = Phone::connect(self.link_addr(), &self.dm.spki_pin())
            .await
            .expect("tls");
        let challenge = ws.expect_challenge().await;
        ws.send(Message::Hello(HelloPayload {
            device_id: paired.device_id.clone(),
            device_token: Secret::new(paired.token.clone()),
            challenge_b64: challenge.challenge_b64,
            protocol: 1,
            app_version: Some("0.1.0".into()),
            last_seq,
            wants_snapshot,
            signature_b64: None,
        }))
        .await;
        ws
    }

    /// `hello` + the `welcome` (and snapshot when requested) consumed.
    pub async fn connect_ready(&self, paired: &PairedPhone) -> Phone {
        let mut ws = self.hello(paired, 0, true).await;
        let f = ws.recv().await.expect("welcome");
        assert!(
            matches!(f.message, Message::Welcome(_)),
            "got {:?}",
            f.message.type_name()
        );
        let f = ws.recv().await.expect("snapshot");
        assert!(
            matches!(f.message, Message::Snapshot(_)),
            "got {:?}",
            f.message.type_name()
        );
        ws
    }

    /// Waits until the daemon sees `n` online devices.
    pub async fn wait_online(&self, n: usize) {
        for _ in 0..400 {
            if self.dm.debug_online_devices().len() == n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {n} online devices");
    }
}

pub fn post_blocking(url: &str, token: &str, body: &Value) -> (u16, String) {
    request_blocking(
        "POST",
        url,
        &[("X-AgentNest-Token", token)],
        Some(body.to_string().into_bytes()),
    )
}

/// Like [`post_blocking`] but a transport error is a value (the daemon may go away mid request).
pub fn post_result(url: &str, token: &str, body: &Value) -> Result<(u16, String), String> {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .proxy(None)
        .build();
    let agent: ureq::Agent = config.into();
    match agent
        .post(url)
        .header("X-AgentNest-Token", token)
        .send(body.to_string().into_bytes())
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            Ok((
                status,
                resp.into_body().read_to_string().unwrap_or_default(),
            ))
        }
        Err(e) => Err(e.to_string()),
    }
}

pub fn request_blocking(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> (u16, String) {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .proxy(None)
        .build();
    let agent: ureq::Agent = config.into();
    let result = if method == "GET" {
        let mut req = agent.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.call()
    } else {
        let mut req = agent.post(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.send(body.unwrap_or_default())
    };
    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            (
                status,
                resp.into_body().read_to_string().unwrap_or_default(),
            )
        }
        Err(e) => panic!("transport error: {e}"),
    }
}

/// The phone's (fake) SPKI: only its bytes matter to the proof.
pub fn phone_spki() -> Vec<u8> {
    use rcgen::PublicKeyData;
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    kp.subject_public_key_info()
}

// ---------------------------------------------------------------------------------------------------------------------
// the phone
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct PinVerifier {
    pin: String,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = agentnest_core::identity::spki_from_cert_der(end_entity.as_ref())
            .ok_or_else(|| rustls::Error::General("no spki".into()))?;
        let got = agentnest_protocol::qr::spki_pin(&spki);
        if got == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("spki pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// What a read from the phone socket can give.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Got {
    Frame(Frame),
    Closed(Option<u16>),
    Timeout,
}

pub struct Phone {
    pub ws: WebSocketStream<Tls>,
    /// Close code received (when the server closed).
    pub closed: Option<u16>,
    /// Raw texts received so far (for the "no secret" greps).
    pub raw: Vec<String>,
    /// Frames `recv_type` skipped while waiting for another type: a later `recv_type` of their type finds them here (a
    /// frame that arrives before the one a test waits for must not be lost - that made some tests flaky).
    stash: std::collections::VecDeque<Frame>,
}

fn client_config(pin: &str) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier {
            pin: pin.to_owned(),
            algs,
        }))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// A pinned TLS connection WITHOUT the WebSocket upgrade (pre-authentication limit tests), optionally from a chosen
/// loopback source address (`127.0.0.N`; Linux accepts any of them).
pub async fn connect_tls(addr: SocketAddr, pin: &str, source: Option<&str>) -> Result<Tls, String> {
    let tcp = match source {
        Some(src) => {
            let sock = tokio::net::TcpSocket::new_v4().map_err(|e| e.to_string())?;
            sock.bind(
                format!("{src}:0")
                    .parse()
                    .map_err(|_| "bad source".to_owned())?,
            )
            .map_err(|e| e.to_string())?;
            sock.connect(addr).await.map_err(|e| e.to_string())?
        }
        None => TcpStream::connect(addr).await.map_err(|e| e.to_string())?,
    };
    let connector = tokio_rustls::TlsConnector::from(client_config(pin));
    connector
        .connect(ServerName::IpAddress(addr.ip().into()), tcp)
        .await
        .map_err(|e| e.to_string())
}

impl Phone {
    pub async fn connect(addr: SocketAddr, pin: &str) -> Result<Phone, String> {
        Self::connect_with(addr, pin, Some(agentnest_protocol::limits::WS_SUBPROTOCOL)).await
    }

    pub async fn connect_with(
        addr: SocketAddr,
        pin: &str,
        subprotocol: Option<&str>,
    ) -> Result<Phone, String> {
        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        Self::over_tcp_with(tcp, addr, pin, subprotocol).await
    }

    /// TLS + WebSocket over an already connected socket (tests choosing the source address).
    pub async fn over_tcp(tcp: TcpStream, addr: SocketAddr, pin: &str) -> Result<Phone, String> {
        Self::over_tcp_with(
            tcp,
            addr,
            pin,
            Some(agentnest_protocol::limits::WS_SUBPROTOCOL),
        )
        .await
    }

    async fn over_tcp_with(
        tcp: TcpStream,
        addr: SocketAddr,
        pin: &str,
        subprotocol: Option<&str>,
    ) -> Result<Phone, String> {
        let connector = tokio_rustls::TlsConnector::from(client_config(pin));
        let name = ServerName::IpAddress(addr.ip().into());
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let mut req = format!("wss://{addr}/v1/link")
            .into_client_request()
            .map_err(|e| e.to_string())?;
        if let Some(p) = subprotocol {
            req.headers_mut()
                .insert("Sec-WebSocket-Protocol", p.parse().unwrap());
        }
        let (ws, _resp) = tokio_tungstenite::client_async(req, tls)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Phone {
            ws,
            closed: None,
            raw: Vec::new(),
            stash: std::collections::VecDeque::new(),
        })
    }

    fn envelope(&self, message: Message) -> String {
        Frame::new(
            uuid::Uuid::now_v7().to_string(),
            "2026-10-15T09:00:00.000Z",
            None,
            message,
        )
        .to_json()
        .unwrap()
    }

    /// Sends a typed frame; returns its envelope id.
    pub async fn send(&mut self, message: Message) -> String {
        let frame = Frame::new(
            uuid::Uuid::now_v7().to_string(),
            "2026-10-15T09:00:00.000Z",
            None,
            message,
        );
        let id = frame.id.clone();
        let _ = self.ws.send(WsMsg::text(frame.to_json().unwrap())).await;
        id
    }

    pub async fn send_raw(&mut self, text: &str) {
        let _ = self.ws.send(WsMsg::text(text.to_owned())).await;
    }

    pub async fn send_binary(&mut self, data: Vec<u8>) {
        let _ = self.ws.send(WsMsg::binary(data)).await;
    }

    /// The next frame, a close, or a timeout.
    pub async fn next(&mut self, timeout: Duration) -> Got {
        if self.closed.is_some() {
            return Got::Closed(self.closed);
        }
        loop {
            match tokio::time::timeout(timeout, self.ws.next()).await {
                Err(_) => return Got::Timeout,
                Ok(None) => return Got::Closed(None),
                Ok(Some(Err(e))) => {
                    eprintln!("ws error: {e}");
                    return Got::Closed(None);
                }
                Ok(Some(Ok(WsMsg::Text(t)))) => {
                    self.raw.push(t.as_str().to_owned());
                    match Frame::parse(t.as_str()) {
                        Ok(f) => return Got::Frame(f),
                        Err(e) => panic!("the PC sent an unparsable frame: {e}: {}", t.as_str()),
                    }
                }
                Ok(Some(Ok(WsMsg::Close(c)))) => {
                    let code = c.map(|f| u16::from(f.code));
                    self.closed = code.or(Some(1005));
                    return Got::Closed(self.closed);
                }
                Ok(Some(Ok(_))) => continue,
            }
        }
    }

    /// The next frame within 5 s.
    pub async fn recv(&mut self) -> Option<Frame> {
        match self.next(Duration::from_secs(5)).await {
            Got::Frame(f) => Some(f),
            _ => None,
        }
    }

    /// The next frame whose type is `t`; frames of other types are skipped. Panics on close/timeout.
    pub async fn recv_type(&mut self, t: &str) -> Frame {
        if let Some(i) = self.stash.iter().position(|f| f.message.type_name() == t) {
            if let Some(f) = self.stash.remove(i) {
                return f;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next(left).await {
                Got::Frame(f) if f.message.type_name() == t => return f,
                Got::Frame(f) => {
                    self.stash.push_back(f);
                    continue;
                }
                other => panic!("waiting for {t}: {other:?}"),
            }
        }
    }

    /// Expects the close and returns its code (frames before it are ignored).
    pub async fn expect_close(&mut self) -> u16 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next(left).await {
                Got::Frame(_) => continue,
                Got::Closed(c) => return c.unwrap_or(0),
                Got::Timeout => panic!("no close within the time limit"),
            }
        }
    }

    /// Like [`Phone::expect_close`] but fails if any frame arrives first (pre-auth silence).
    pub async fn expect_silent_close(&mut self) -> u16 {
        match self.next(Duration::from_secs(10)).await {
            Got::Closed(c) => c.unwrap_or(0),
            Got::Frame(f) => panic!(
                "unexpected frame before the close: {}",
                f.message.type_name()
            ),
            Got::Timeout => panic!("no close"),
        }
    }

    pub async fn expect_challenge(&mut self) -> agentnest_protocol::ChallengePayload {
        match self.recv().await.map(|f| f.message) {
            Some(Message::Challenge(c)) => c,
            other => panic!("expected a challenge, got {other:?}"),
        }
    }

    /// Reads frames until an `approval_request`, acks it and returns the card.
    pub async fn recv_card(&mut self) -> (ApprovalRequest, i64) {
        let f = self.recv_type("approval_request").await;
        let seq = f.seq.unwrap_or(0);
        let Message::ApprovalRequest(card) = f.message else {
            unreachable!()
        };
        self.send(Message::Ack(agentnest_protocol::AckPayload {
            through_seq: Some(seq),
            approval_ids: vec![card.request_id.clone()],
        }))
        .await;
        (*card, seq)
    }

    /// A valid decision frame for `card` (a biometric claim attached).
    pub fn decision_for(card: &ApprovalRequest, decision: Decision) -> DecisionPayload {
        let extra = match (&card.risk.extra_confirmation, decision) {
            (_, Decision::Deny) | (agentnest_protocol::ExtraConfirmation::None, _) => None,
            (agentnest_protocol::ExtraConfirmation::Hold, _) => {
                Some(agentnest_protocol::ExtraConfirmationProof {
                    method: agentnest_protocol::ExtraConfirmationMethod::Hold,
                    completed: true,
                })
            }
            _ => Some(agentnest_protocol::ExtraConfirmationProof {
                method: agentnest_protocol::ExtraConfirmationMethod::HoldAndReconfirm,
                completed: true,
            }),
        };
        DecisionPayload {
            request_id: card.request_id.clone(),
            session_key: card.session_key.clone(),
            nonce_b64: Secret::new(card.nonce_b64.expose()),
            tool_input_sha256: card.tool_input_sha256.clone(),
            decision,
            reason: None,
            decided_at: now_iso(),
            auth: Some(DecisionAuth {
                method: agentnest_protocol::AuthMethod::Biometric,
                authenticated_at: Some(now_iso()),
            }),
            extra_confirmation: extra,
            signature_b64: None,
        }
    }

    /// Sends a decision and returns the matching `decision_result`.
    pub async fn decide(
        &mut self,
        p: DecisionPayload,
    ) -> agentnest_protocol::DecisionResultPayload {
        let id = self.send(Message::Decision(p)).await;
        let f = self.recv_type("decision_result").await;
        let Message::DecisionResult(r) = f.message else {
            unreachable!()
        };
        assert_eq!(r.in_reply_to, id);
        r
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }

    pub fn unused(&self) -> CloseCode {
        CloseCode::Normal
    }
}

pub fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

// ---------------------------------------------------------------------------------------------------------------------
// pairing
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Tweak {
    None,
    WrongProof,
    WrongChallenge,
    UnknownPairingId,
}

pub struct PairedPhone {
    pub device_id: String,
    pub token: String,
    pub name: String,
    /// The pairing connection, which carries on as an authenticated session (welcome + snapshot follow).
    pub ws: Option<Phone>,
}

pub struct PairAttempt {
    pub ws: Phone,
    pub pairing_id: String,
    pub want_sas: String,
    pub started: Option<agentnest_core::auth::pairing::PairingStarted>,
    pub dm_events: broadcast::Receiver<DaemonEvent>,
    pub pin: String,
    pub addr: SocketAddr,
    pub name: String,
}

impl PairAttempt {
    /// Reads `pair_pending` and returns the SAS the PC shows.
    pub async fn pending_sas(&mut self) -> String {
        let f = self.ws.recv_type("pair_pending").await;
        let Message::PairPending(p) = f.message else {
            unreachable!()
        };
        p.sas
    }

    /// The SAS the PC UI shows (daemon event).
    pub async fn pc_sas(&mut self) -> String {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), self.dm_events.recv()).await {
                Ok(Ok(DaemonEvent::Pairing(PairingUiEvent::ConfirmRequested { sas, .. }))) => {
                    return sas
                }
                Ok(Ok(_)) => continue,
                other => panic!("no ConfirmRequested: {other:?}"),
            }
        }
    }

    /// Reads the successful `pair_result`.
    pub async fn finish(mut self) -> PairedPhone {
        let f = self.ws.recv_type("pair_result").await;
        let Message::PairResult(r) = f.message else {
            unreachable!()
        };
        assert!(r.ok, "pairing failed: {:?}", r.error_code);
        PairedPhone {
            device_id: r.device_id.expect("device_id"),
            token: r.device_token.expect("device_token").expose().to_owned(),
            name: self.name,
            ws: Some(self.ws),
        }
    }

    /// Reads a failed `pair_result` and the close; returns the error code and the close code.
    pub async fn expect_failure(mut self) -> (Option<ErrorCode>, u16) {
        let f = self.ws.recv_type("pair_result").await;
        let Message::PairResult(r) = f.message else {
            unreachable!()
        };
        assert!(!r.ok);
        assert!(r.device_token.is_none() && r.device_id.is_none());
        let close = self.ws.expect_close().await;
        (r.error_code, close)
    }
}
