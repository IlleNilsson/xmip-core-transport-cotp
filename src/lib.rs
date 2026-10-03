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
//!
//! **Acceptance is at-most-once here** ([`AT_MOST_ONCE`]): COTP class 0
//! acknowledges no data TPDU, and the caller's DR ends the connection
//! without waiting for an answer, so nobody is told how the receive cycle
//! ended. Each message arrives whole, as the TPDUs carried it.

pub mod connection;
pub mod tpdu;
pub mod tpkt;

use std::net::TcpListener;
use std::time::Duration;

pub use connection::Connection;
use net::Target;
pub use tpdu::{Connect, Tpdu};
use transport::error::{Result, protocol_error};
use transport::kept::Kept;
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Acknowledgement, Arrived, Configured, Directions, Taken, Transport};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

/// Why a COTP message cannot be acknowledged after the receive cycle.
pub const AT_MOST_ONCE: &str = "COTP class 0 acknowledges no data: the caller's DR ends the \
                                connection without waiting for an answer";

#[derive(Clone)]
pub struct CotpTransport {
    bind: String,
    local_tsap: Vec<u8>,
    remote_tsap: Vec<u8>,
    size_code: u8,
    timeout: Option<Duration>,
    /// The listener the first receive binds, and every receive takes from.
    receiving: Kept<TcpListener>,
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
            receiving: Kept::new(),
        }
    }

    /// The TSAPs a call is made between: this side's, then the far end's.
    #[must_use]
    fn with_tsaps(mut self, local: impl Into<Vec<u8>>, remote: impl Into<Vec<u8>>) -> Self {
        self.local_tsap = local.into();
        self.remote_tsap = remote.into();
        self
    }

    /// Propose, or accept at most, a TPDU of 2^`code` bytes; 7 to 13.
    #[must_use]
    const fn with_tpdu_size_code(mut self, code: u8) -> Self {
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
        let Some(named) = Target::under(&["cotp"], target) else {
            return Ok((
                target.to_string(),
                self.local_tsap.clone(),
                self.remote_tsap.clone(),
            ));
        };
        let mut local = self.local_tsap.clone();
        let mut remote = self.remote_tsap.clone();
        for (key, value) in named.query() {
            let tsap = codec::hex::decode(&value)
                .map_err(|_| protocol_error(format!("{value:?} is not a TSAP in hex")))?;
            match key.as_str() {
                "src-tsap" => local = tsap,
                "dst-tsap" => remote = tsap,
                _ => {}
            }
        }
        Ok((named.authority().to_string(), local, remote))
    }
}

impl Transport for CotpTransport {
    fn name(&self) -> &'static str {
        "cotp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a caller's messages are taken in order until it disconnects")
    }

    /// One caller's messages until it disconnects, from the listener the
    /// first receive bound and kept, each whole. Acceptance is at-most-once
    /// here: class 0 has no answer to defer ([`AT_MOST_ONCE`]).
    fn receive(&self) -> Result<Vec<Arrived>> {
        let listener = self.receiving.bound(|| self.bind())?;
        let mut connection = self.accept_one(listener)?;
        let origin = connection.origin();
        let mut arrived = Vec::new();
        while let Some(message) = connection.next_data()? {
            arrived.push(Arrived::whole(
                origin.clone(),
                message,
                Acknowledgement::at_most_once(AT_MOST_ONCE),
            ));
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

impl Configured for CotpTransport {
    /// The address is where a Receive Location listens — `0.0.0.0:102` the
    /// standard port; a Send Location calls the target its route gives.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "src_tsap",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "This side's TSAP a call is made from, in hex; the usual client \
                          TSAP when left out.",
                applies: Applies::Send,
            },
            Setting {
                name: "dst_tsap",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The far end's TSAP a call is made to, in hex; the usual server \
                          TSAP when left out.",
                applies: Applies::Send,
            },
            Setting {
                name: "tpdu_size_code",
                kind: Kind::Integer {
                    minimum: 7,
                    maximum: 13,
                },
                presence: Presence::Default(Fixed::Integer(tpdu::DEFAULT_SIZE_CODE as i64)),
                meaning: "The TPDU size proposed or accepted at most, as the power of two \
                          of its bytes.",
                applies: Applies::Both,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a peer that stops mid-message is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let size_code = u8::try_from(settings.integer("tpdu_size_code"))
            .map_err(|_| protocol_error("a TPDU size code out of range"))?;
        let mut transport = Self::new(address).with_tpdu_size_code(size_code);
        let tsap = |name: &str| -> Result<Option<Vec<u8>>> {
            settings
                .optional_text(name)
                .map(|hex| {
                    codec::hex::decode(hex)
                        .map_err(|_| protocol_error(format!("{name} {hex:?} is not hex")))
                })
                .transpose()
        };
        let local = tsap("src_tsap")?.unwrap_or_else(|| transport.local_tsap.clone());
        let remote = tsap("dst_tsap")?.unwrap_or_else(|| transport.remote_tsap.clone());
        transport = transport.with_tsaps(local, remote);
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport)
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
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        let mut connection = self.accept_one(listener)?;
        let message = connection
            .next_data()?
            .ok_or_else(|| protocol_error("the caller disconnected without a message"))?;
        // See the DR that follows, so the goodbye is read rather than met
        // with a closed socket.
        connection.next_data()?;
        Ok(Taken::new(connection.origin(), message))
    }
}

impl Loopback for CotpTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
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
    use xcore::settings::Given;

    #[test]
    fn every_receive_takes_from_the_listener_the_first_bound() {
        let receiver = CotpTransport::loopback();
        receiver.receiving.bound(|| receiver.bind()).expect("bound");
        let address = receiver.receiving.address().expect("address");
        transport::kept::held_across_receives(&receiver, address, 5, |at, payload| {
            CotpTransport::loopback().send_to(at, payload)
        });
    }

    #[test]
    fn cotp_declares_its_settings_and_reads_through_them() {
        assert_eq!(CotpTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("dst_tsap".to_string(), Given::Text("0301".to_string())),
            ("tpdu_size_code".to_string(), Given::Integer(9)),
        ];
        let built = CotpTransport::open("0.0.0.0:102", Applies::Send, &given).expect("built");
        assert_eq!(built.remote_tsap, [0x03, 0x01]);
        assert_eq!(built.local_tsap, [0x01, 0x00]);
        assert_eq!(built.size_code, 9);
        let given = [("tpdu_size_code".to_string(), Given::Integer(14))];
        let Err(refused) = CotpTransport::open("0.0.0.0:102", Applies::Receive, &given) else {
            panic!("14 is over the range");
        };
        assert!(
            refused.message.contains("\"tpdu_size_code\""),
            "{}",
            refused.message
        );
    }

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
        assert!(arrived.iter().all(|one| !one.defers()), "at-most-once");
        let arrived: Vec<Taken> = arrived
            .into_iter()
            .map(|one| one.taken().expect("taken"))
            .collect();
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
