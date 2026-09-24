//! One ISO transport connection: the handshake that opens it, messages
//! segmented into DT TPDUs on the way out and reassembled on the way in, and
//! the DR that closes it.
//!
//! Class 0 has no flow control, no acknowledgement and no sequence numbers —
//! TCP underneath does all of that — so a connection is a pair of TSAPs, a
//! negotiated TPDU size, and the EOT bit that says where one message ends
//! and the next begins.

use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use codec::hex;
use transport::error::{Result, protocol_error};
use transport::socket;

use crate::tpdu::{self, Connect, Tpdu};
use crate::tpkt;

/// A connected pair of TSAPs and what they agreed on.
pub struct Connection {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    local_tsap: Vec<u8>,
    remote_tsap: Vec<u8>,
    tpdu_size: usize,
}

impl Connection {
    /// Call `address` from `local_tsap` to `remote_tsap`, proposing 2^`size_code`
    /// as the TPDU size, and take the confirm.
    ///
    /// # Errors
    /// Where the peer could not be reached, refused with DR, or answered CR
    /// with anything but CC.
    pub fn connect(
        address: &str,
        local_tsap: &[u8],
        remote_tsap: &[u8],
        size_code: u8,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(address, timeout)?;
        let peer = stream
            .peer_addr()
            .map_err(|e| transport::error::classify("reading the peer address", &e))?;
        let (reader, writer) = socket::split(stream)?;
        let mut connection = Self {
            reader,
            writer,
            peer,
            local_tsap: local_tsap.to_vec(),
            remote_tsap: remote_tsap.to_vec(),
            tpdu_size: tpdu::size_of(size_code),
        };
        connection.write(&Tpdu::ConnectRequest(Connect {
            src_ref: 1,
            dst_ref: 0,
            size_code,
            src_tsap: local_tsap.to_vec(),
            dst_tsap: remote_tsap.to_vec(),
        }))?;
        match connection.read()? {
            Some(Tpdu::ConnectConfirm(confirm)) => {
                connection.tpdu_size = tpdu::size_of(confirm.size_code.min(size_code));
            }
            Some(Tpdu::Disconnect { reason }) => {
                return Err(protocol_error(format!(
                    "the peer refused the connection, reason {reason:#04x}"
                )));
            }
            _ => return Err(protocol_error("the peer did not answer CR with CC")),
        }
        Ok(connection)
    }

    /// Accept one caller on `listener` and answer its CR with CC, settling on
    /// the smaller of its size and 2^`size_code`.
    ///
    /// # Errors
    /// Where the connection could not be accepted or did not open with CR.
    pub fn accept(
        listener: &TcpListener,
        size_code: u8,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut connection = Self {
            reader,
            writer,
            peer,
            local_tsap: Vec::new(),
            remote_tsap: Vec::new(),
            tpdu_size: tpdu::size_of(size_code),
        };
        let Some(Tpdu::ConnectRequest(request)) = connection.read()? else {
            connection.write(&Tpdu::Disconnect { reason: 0x80 })?;
            return Err(protocol_error("the caller did not open with CR"));
        };
        let size_code = request.size_code.min(size_code);
        connection.tpdu_size = tpdu::size_of(size_code);
        connection.remote_tsap.clone_from(&request.src_tsap);
        connection.local_tsap.clone_from(&request.dst_tsap);
        connection.write(&Tpdu::ConnectConfirm(Connect {
            src_ref: 2,
            dst_ref: request.src_ref,
            size_code,
            src_tsap: request.dst_tsap,
            dst_tsap: request.src_tsap,
        }))?;
        Ok(connection)
    }

    /// The far end's address.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// This side's TSAP.
    #[must_use]
    pub fn local_tsap(&self) -> &[u8] {
        &self.local_tsap
    }

    /// The far end's TSAP.
    #[must_use]
    pub fn remote_tsap(&self) -> &[u8] {
        &self.remote_tsap
    }

    /// The TPDU size settled on.
    #[must_use]
    pub const fn tpdu_size(&self) -> usize {
        self.tpdu_size
    }

    /// Where a message on this connection came from, as an origin URI:
    /// `cotp://peer?src-tsap=0100&dst-tsap=0102` — the peer's TSAP first,
    /// then this side's, as a CR from the peer would name them.
    #[must_use]
    pub fn origin(&self) -> String {
        format!(
            "cotp://{}?src-tsap={}&dst-tsap={}",
            self.peer,
            hex::encode(&self.remote_tsap),
            hex::encode(&self.local_tsap)
        )
    }

    /// Send one message, in as many DT segments as the TPDU size takes.
    ///
    /// # Errors
    /// Where the peer went away.
    pub fn send_data(&mut self, bytes: &[u8]) -> Result<()> {
        let segment = self.tpdu_size - 3;
        let mut chunks = bytes.chunks(segment).peekable();
        if chunks.peek().is_none() {
            return self.write(&Tpdu::Data {
                last: true,
                payload: Vec::new(),
            });
        }
        while let Some(chunk) = chunks.next() {
            self.write(&Tpdu::Data {
                last: chunks.peek().is_none(),
                payload: chunk.to_vec(),
            })?;
        }
        Ok(())
    }

    /// The next whole message, or `None` when the peer disconnected or closed
    /// between messages.
    ///
    /// # Errors
    /// A connection that breaks mid-message, or a TPDU that is not data.
    pub fn next_data(&mut self) -> Result<Option<Vec<u8>>> {
        let mut message = Vec::new();
        loop {
            match self.read()? {
                Some(Tpdu::Data { last, payload }) => {
                    message.extend_from_slice(&payload);
                    if last {
                        return Ok(Some(message));
                    }
                }
                Some(Tpdu::Disconnect { .. }) => return Ok(None),
                None if message.is_empty() => return Ok(None),
                None => return Err(protocol_error("the peer closed mid-message")),
                Some(_) => return Err(protocol_error("a connect TPDU on an open connection")),
            }
        }
    }

    /// End the connection with DR.
    ///
    /// # Errors
    /// Where the peer had already gone.
    pub fn disconnect(mut self) -> Result<()> {
        self.write(&Tpdu::Disconnect { reason: 0 })
    }

    fn write(&mut self, tpdu: &Tpdu) -> Result<()> {
        tpkt::write_frame(&mut self.writer, &tpdu::encode(tpdu))
    }

    fn read(&mut self) -> Result<Option<Tpdu>> {
        match tpkt::read_frame(&mut self.reader)? {
            Some(frame) => tpdu::decode(&frame).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_message_is_segmented_and_reassembled() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let long: Vec<u8> = (0..3000u32)
            .map(|n| u8::try_from(n % 251).expect("fits"))
            .collect();
        let sent = long.clone();
        let caller = std::thread::spawn(move || {
            let mut connection =
                Connection::connect(&address, &[1, 0], &[1, 2], 7, Some(secs(2))).expect("c");
            assert_eq!(connection.tpdu_size(), 128, "the smaller side wins");
            connection.send_data(&sent).expect("long");
            connection.send_data(b"").expect("empty");
            connection.disconnect().expect("dr");
        });
        let mut connection = Connection::accept(&listener, 10, Some(secs(2))).expect("accept");
        assert_eq!(connection.remote_tsap(), &[1, 0]);
        assert_eq!(connection.local_tsap(), &[1, 2]);
        assert!(
            connection
                .origin()
                .ends_with("?src-tsap=0100&dst-tsap=0102")
        );
        assert_eq!(connection.next_data().expect("long"), Some(long));
        assert_eq!(connection.next_data().expect("empty"), Some(Vec::new()));
        assert!(connection.next_data().expect("dr").is_none());
        caller.join().expect("thread");
    }

    #[test]
    fn a_caller_that_does_not_open_with_cr_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let caller = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect");
            tpkt::write_frame(&mut stream, &[2, 0xF0, 0x80, b'x']).expect("dt");
            let mut reader = BufReader::new(stream);
            tpkt::read_frame(&mut reader).expect("answer")
        });
        let error = Connection::accept(&listener, 10, Some(secs(2)))
            .err()
            .expect("refused");
        assert!(!error.retryable);
        let answer = caller.join().expect("thread").expect("dr");
        assert_eq!(answer[1], 0x80, "answered with DR");
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }
}
