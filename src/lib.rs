#![forbid(unsafe_code)]

//! Streams that arrive over ISO transport on TCP. One COTP message — a run
//! of DT TPDUs up to the one with EOT set — is one Stream.
//!
//! RFC 1006 is how the OSI transport layer survived: TPKT puts a four-byte
//! frame around each TPDU so a TCP byte stream carries packets, and COTP
//! class 0 above it adds a connect handshake naming both transport service
//! access points, a negotiated TPDU size, and data segmented to that size.
//! Siemens S7, IEC 61850 MMS and the rest of the ISO-on-TCP family ride on
//! exactly this, on port 102, which is why it is its own technology rather
//! than three private copies. A Receive Location listens and hands each
//! message up as a Stream; a Send Location connects, delivers one message,
//! and disconnects.
//!
//! The origin URI carries what the handshake knew:
//! `cotp://peer?src-tsap=0100&dst-tsap=0102`, TSAPs in hex, the caller's
//! first. A target is `cotp://host:102`, optionally with the same query to
//! name the TSAPs for that one call, or a bare `host:port` using the
//! configured ones.

pub mod connection;
pub mod tpdu;
pub mod tpkt;

use std::net::TcpListener;
use std::time::Duration;

pub use connection::Connection;
pub use tpdu::{Connect, Tpdu};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, Transport};

#[derive(Clone)]
pub struct CotpTransport {
    bind: String,
    local_tsap: Vec<u8>,
    remote_tsap: Vec<u8>,
    size_code: u8,
    timeout: Option<Duration>,
}

impl CotpTransport {
    /// Listen at `bind`; `0.0.0.0:102` is the standard port. Calls go out
    /// from TSAP `0100` to TSAP `0102` until [`Self::with_tsaps`] says
    /// otherwise, proposing a 1024-byte TPDU.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            local_tsap: vec![0x01, 0x00],
            remote_tsap: vec![0x01, 0x02],
            size_code: tpdu::DEFAULT_SIZE_CODE,
            timeout: None,
        }
    }

    /// The TSAPs a call is made between: this side's, then the far end's.
    #[must_use]
    pub fn with_tsaps(mut self, local: impl Into<Vec<u8>>, remote: impl Into<Vec<u8>>) -> Self {
        self.local_tsap = local.into();
        self.remote_tsap = remote.into();
        self
    }

    /// Propose, or accept at most, a TPDU of 2^`code` bytes; 7 to 13.
    #[must_use]
    pub const fn with_tpdu_size_code(mut self, code: u8) -> Self {
        self.size_code = code;
        self
    }

    /// Give up on a peer that stops mid-message.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind the listener and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.bind)
    }

    /// Accept one caller on an already-bound listener, answering its CR.
    ///
    /// # Errors
    /// Where the connection could not be accepted or did not open with CR.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Connection> {
        Connection::accept(listener, self.size_code, self.timeout)
    }

    /// Call `address` between the configured TSAPs.
    ///
    /// # Errors
    /// Where the peer could not be reached or refused the connection.
    pub fn connect(&self, address: &str) -> Result<Connection> {
        Connection::connect(
            address,
            &self.local_tsap,
            &self.remote_tsap,
            self.size_code,
            self.timeout,
        )
    }

    /// `cotp://host:102?src-tsap=..&dst-tsap=..` or `host:port` as the
    /// address and the TSAPs to call between.
    ///
    /// # Errors
    /// A TSAP in the query that is not hex.
    pub fn resolve(&self, target: &str) -> Result<(String, Vec<u8>, Vec<u8>)> {
        let Some((authority, _)) = socket::target("cotp", target) else {
            return Ok((
                target.to_string(),
                self.local_tsap.clone(),
                self.remote_tsap.clone(),
            ));
        };
        let (address, query) = authority.split_once('?').unwrap_or((authority, ""));
        let mut local = self.local_tsap.clone();
        let mut remote = self.remote_tsap.clone();
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let tsap = codec::hex::decode(value)
                .map_err(|_| protocol_error(format!("{value:?} is not a TSAP in hex")))?;
            match key {
                "src-tsap" => local = tsap,
                "dst-tsap" => remote = tsap,
                _ => {}
            }
        }
        Ok((address.to_string(), local, remote))
    }
}

impl Transport for CotpTransport {
    fn name(&self) -> &'static str {
        "cotp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// One caller's messages until it disconnects.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let (listener, _) = self.bind()?;
        let mut connection = self.accept_one(&listener)?;
        let origin = connection.origin();
        let mut arrived = Vec::new();
        while let Some(message) = connection.next_data()? {
            arrived.push(Arrived::new(origin.clone(), message));
        }
        Ok(arrived)
    }

    /// Connect, deliver one message, disconnect.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (address, local, remote) = self.resolve(target)?;
        let mut connection =
            Connection::connect(&address, &local, &remote, self.size_code, self.timeout)?;
        connection.send_data(bytes)?;
        connection.disconnect()
    }
}

impl CotpTransport {
    /// Both ends on this machine: an ephemeral local port, the default
    /// TSAPs, the loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for CotpTransport {
    fn take_one(&self, listener: &TcpListener) -> Result<Arrived> {
        let mut connection = self.accept_one(listener)?;
        let message = connection
            .next_data()?
            .ok_or_else(|| protocol_error("the caller disconnected without a message"))?;
        // See the DR that follows, so the goodbye is read rather than met
        // with a closed socket.
        connection.next_data()?;
        Ok(Arrived::new(connection.origin(), message))
    }
}

impl Loopback for CotpTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening::new(self.clone(), listener, address)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new("127.0.0.1:0")
            .with_tsaps(self.local_tsap.clone(), self.remote_tsap.clone())
            .with_tpdu_size_code(self.size_code)
            .timing_out_after(LOOPBACK_TIMEOUT)
            .send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;

    fn node() -> CotpTransport {
        CotpTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2))
    }

    /// Three thousand bytes that are not all alike, so a segment out of
    /// order would show.
    fn long() -> Vec<u8> {
        (0..=255u8).cycle().take(3000).collect()
    }

    #[test]
    fn the_loopback_delivers_one_message_as_segments_and_takes_it() {
        let arrived = CotpTransport::loopback().round(b"one tpdu").expect("round");
        assert_eq!(arrived.bytes, b"one tpdu");
        assert!(arrived.origin_uri.starts_with("cotp://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("?src-tsap=0100&dst-tsap=0102"));
        let long = long();
        assert_eq!(
            CotpTransport::loopback().round(&long).expect("long").bytes,
            long
        );
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let transport = CotpTransport::loopback();
        assert!(transport.ceiling().is_none());
        for (name, bytes) in edge_payloads() {
            assert!(transport.refuses(&bytes).is_none(), "{name}");
            let arrived = transport
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_call_delivers_one_message_between_its_tsaps() {
        let far_end = node();
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            node()
                .with_tsaps(b"XMIP".to_vec(), b"PLC".to_vec())
                .send(&address, &[0u8; 2000])?;
            node().send(&format!("cotp://{address}?dst-tsap=0201"), b"second")
        });
        let mut connection = far_end.accept_one(&listener).expect("accepting");
        assert_eq!(connection.remote_tsap(), b"XMIP");
        assert_eq!(
            connection.next_data().expect("first"),
            Some(vec![0u8; 2000])
        );
        assert!(connection.next_data().expect("dr").is_none());
        let mut connection = far_end.accept_one(&listener).expect("second");
        assert!(
            connection
                .origin()
                .ends_with("?src-tsap=0100&dst-tsap=0201")
        );
        assert_eq!(
            connection.next_data().expect("second"),
            Some(b"second".to_vec())
        );
        sender.join().expect("thread").expect("sending");
    }

    #[test]
    fn receive_takes_a_callers_messages_until_it_disconnects() {
        // A port the kernel just handed out and nobody else has yet: the
        // receiver binds it, and the caller retries until it is listening.
        let (listener, address) = node().bind().expect("a free port");
        drop(listener);
        let far_end = address.clone();
        let receiver = std::thread::spawn(move || node_at(&far_end).receive());
        let mut connection = None;
        for _ in 0..100 {
            if let Ok(open) = node().with_tsaps(vec![2, 1], vec![1, 2]).connect(&address) {
                connection = Some(open);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut connection = connection.expect("the receiver came up");
        connection.send_data(b"first").expect("first");
        connection.send_data(&[7u8; 1500]).expect("second");
        connection.disconnect().expect("dr");
        let arrived = receiver.join().expect("thread").expect("receiving");
        assert_eq!(arrived.len(), 2);
        assert_eq!(arrived[0].bytes, b"first");
        assert_eq!(arrived[1].bytes, [7u8; 1500]);
        assert!(arrived[0].origin_uri.starts_with("cotp://127.0.0.1:"));
        assert!(
            arrived[0]
                .origin_uri
                .ends_with("?src-tsap=0201&dst-tsap=0102")
        );
    }

    fn node_at(bind: &str) -> CotpTransport {
        CotpTransport::new(bind).timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn a_target_resolves_and_what_is_not_cotp_is_refused() {
        let (address, local, remote) = node()
            .resolve("cotp://plc:102?src-tsap=0100&dst-tsap=0201")
            .expect("resolved");
        assert_eq!(
            (address.as_str(), local, remote),
            ("plc:102", vec![1, 0], vec![2, 1])
        );
        assert_eq!(node().resolve("plc:102").expect("bare").0, "plc:102");
        assert!(node().resolve("cotp://plc?dst-tsap=zz").is_err());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far_end = std::thread::spawn(move || {
            // Take the CR first, so the banner is what the caller reads
            // rather than a reset from closing on unread bytes.
            let (mut stream, _) = listener.accept().expect("accept");
            let mut cr = [0u8; 64];
            let _ = std::io::Read::read(&mut stream, &mut cr);
            std::io::Write::write_all(&mut stream, b"220 mail.example ESMTP\r\n").expect("w");
            std::thread::sleep(Duration::from_millis(200));
        });
        let error = node().send(&address, b"x").expect_err("refused");
        assert!(!error.retryable, "{error}");
        far_end.join().expect("thread");
        assert!(node().claims().is_none());
        assert_eq!(node().name(), "cotp");
    }
}
